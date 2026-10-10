import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Store } from "../src/store/store.js";
import { BanStore } from "../src/bans/store.js";
import { BanEnforcer } from "../src/bans/enforcer.js";
import { BanService } from "../src/bans/service.js";
import { rangesOverlap } from "../src/ingest/networks.js";
import {
  BlockedPaths,
  blockedPathsRegex,
  isValidBlockedPattern,
  requestPath,
} from "../src/threats/blockedPaths.js";
import { defaultConfig } from "../src/threats/detectors.js";
import { invalidBlockedPatterns, sanitizeThreatConfig } from "../src/threats/validate.js";
import type { ThreatConfig } from "../src/threats/types.js";
import type { AccessEntry } from "../src/types.js";

function matcher(patterns: string[]): (uri: string) => boolean {
  const src = blockedPathsRegex(patterns);
  const re = src ? new RegExp(src, "i") : null;
  return (uri) => re?.test(requestPath(uri)) ?? false;
}

describe("blocked path patterns", () => {
  it("accepts file names, extensions and rooted paths", () => {
    expect(isValidBlockedPattern("wp-trackback.php")).toBe(true);
    expect(isValidBlockedPattern("*.php")).toBe(true);
    expect(isValidBlockedPattern("/wp-admin/*")).toBe(true);
  });

  it("rejects characters that could escape the nginx directive", () => {
    expect(isValidBlockedPattern('*.php" { return 200; } #')).toBe(false);
    expect(isValidBlockedPattern("a;b")).toBe(false);
    expect(isValidBlockedPattern("(.*)")).toBe(false);
    expect(isValidBlockedPattern("a b")).toBe(false);
    expect(isValidBlockedPattern("$host")).toBe(false);
  });

  it("rejects patterns that would block every request", () => {
    expect(isValidBlockedPattern("*")).toBe(false);
    expect(isValidBlockedPattern("/*")).toBe(false);
    expect(isValidBlockedPattern("/")).toBe(false);
  });

  it("matches an extension in any directory, ignoring the query", () => {
    const m = matcher(["*.php"]);
    expect(m("/index.php")).toBe(true);
    expect(m("/a/b/shell.PHP?x=1")).toBe(true);
    expect(m("/php/readme.md")).toBe(false);
    expect(m("/page?file=x.php")).toBe(false);
    expect(m("/x.php5")).toBe(false);
  });

  it("matches a file name in any directory but not as a substring", () => {
    const m = matcher(["wp-trackback.php"]);
    expect(m("/wp-trackback.php")).toBe(true);
    expect(m("/blog/wp-trackback.php?p=1")).toBe(true);
    expect(m("/old-wp-trackback.php")).toBe(false);
  });

  it("matches rooted paths from the start", () => {
    const m = matcher(["/wp-admin/*"]);
    expect(m("/wp-admin/install.php")).toBe(true);
    expect(m("/wp-admin/css/a.css")).toBe(true);
    expect(m("/blog/wp-admin/x")).toBe(false);
  });

  it("sees through encoding, dot segments and doubled slashes like nginx", () => {
    const m = matcher(["*.php", "/wp-admin/*"]);
    expect(m("/shell%2Ephp")).toBe(true);
    expect(m("/static/../wp-admin/x")).toBe(true);
    expect(m("//wp-admin//x")).toBe(true);
  });
});

describe("blocked paths config", () => {
  it("is off by default with suggested patterns", () => {
    const cfg = defaultConfig();
    expect(cfg.blockedPaths.block).toBe(false);
    expect(cfg.blockedPaths.autoBan).toBe(false);
    expect(cfg.blockedPaths.patterns).toContain("*.php");
  });

  it("reports invalid patterns and drops them when sanitising", () => {
    const input = {
      blockedPaths: { block: true, autoBan: true, patterns: ["*.php", "bad;one", "*"] },
    };
    expect(invalidBlockedPatterns(input)).toEqual(["bad;one", "*"]);
    const clean = sanitizeThreatConfig(input);
    expect(clean.blockedPaths).toEqual({ block: true, autoBan: true, patterns: ["*.php"] });
  });
});

const NOW = Date.now();

function entry(over: Partial<AccessEntry>): AccessEntry {
  return {
    hostId: 1,
    source: "proxy-host-1_access.log",
    ts: NOW - 5_000,
    status: 444,
    upstreamStatus: null,
    cacheStatus: null,
    method: "GET",
    scheme: "https",
    host: "example.com",
    uri: "/xmlrpc.php",
    client: "198.51.100.40",
    bytes: 0,
    gzip: null,
    sentTo: null,
    userAgent: "Mozilla/5.0",
    referer: "-",
    ...over,
  };
}

describe("BlockedPaths", () => {
  let store: Store;
  let dir: string;
  let cfg: ThreatConfig;
  let bans: BanService;
  let blocked: BlockedPaths;

  beforeEach(() => {
    store = new Store(":memory:");
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "blocked-"));
    cfg = defaultConfig();
    cfg.blockedPaths = { block: true, autoBan: true, patterns: ["*.php", "/wp-admin/*"] };
    cfg.exceptions = ["203.0.113.0/24"];
    const enforcer = new BanEnforcer({
      customDir: dir,
      dockerSocket: "/nonexistent.sock",
      npmContainer: "",
      log: () => {},
    });
    bans = new BanService(new BanStore(store.db), enforcer, (t) =>
      cfg.exceptions.some((e) => rangesOverlap(t, e)),
    );
    blocked = new BlockedPaths(() => cfg, bans, enforcer);
  });
  afterEach(() => {
    blocked.stop();
    store.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("writes a 444 location and includes it from server_proxy.conf", async () => {
    await blocked.apply();
    const snippet = fs.readFileSync(path.join(dir, "proxylogs-blocked-paths.conf"), "utf8");
    expect(snippet).toContain('location ~* "(?:/[^/]*\\.php$|^/wp-admin/.*$)"');
    expect(snippet).toContain("return 444;");
    const serverProxy = fs.readFileSync(path.join(dir, "server_proxy.conf"), "utf8");
    expect(serverProxy).toContain("/data/nginx/custom/proxylogs-blocked-paths.conf");
  });

  it("writes an empty snippet when blocking is off, keeping the include valid", async () => {
    cfg.blockedPaths.block = false;
    await blocked.apply();
    const snippet = fs.readFileSync(path.join(dir, "proxylogs-blocked-paths.conf"), "utf8");
    expect(snippet).not.toContain("location");
  });

  it("bans a client that requests a blocked path", async () => {
    blocked.handle(entry({}), NOW);
    await blocked.flush(NOW);
    const list = bans.list();
    expect(list.map((b) => b.ip)).toEqual(["198.51.100.40"]);
    expect(list[0]?.reason).toBe("blocked path: /xmlrpc.php");
    const deny = fs.readFileSync(path.join(dir, "proxylogs-bans.conf"), "utf8");
    expect(deny).toContain("deny 198.51.100.40;");
  });

  it("ignores old lines, private, excepted and non-matching clients", async () => {
    blocked.handle(entry({ ts: NOW - 60 * 60_000 }), NOW); // re-read history
    blocked.handle(entry({ client: "192.168.1.5" }), NOW);
    blocked.handle(entry({ client: "203.0.113.9" }), NOW);
    blocked.handle(entry({ client: "198.51.100.41", uri: "/index.html" }), NOW);
    await blocked.flush(NOW);
    expect(bans.list()).toHaveLength(0);
  });

  it("does nothing when instant ban is off", async () => {
    cfg.blockedPaths.autoBan = false;
    await blocked.apply();
    blocked.handle(entry({}), NOW);
    await blocked.flush(NOW);
    expect(bans.list()).toHaveLength(0);
  });
});
