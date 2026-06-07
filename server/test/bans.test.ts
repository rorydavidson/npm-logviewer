import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Store } from "../src/store/store.js";
import { Settings } from "../src/store/settings.js";
import { Mailer } from "../src/threats/mailer.js";
import { ThreatEngine } from "../src/threats/engine.js";
import { BanStore, isValidBanTarget } from "../src/bans/store.js";
import { BanEnforcer } from "../src/bans/enforcer.js";
import { BanService } from "../src/bans/service.js";
import { ipMatchesAny } from "../src/ingest/networks.js";
import type { AccessEntry } from "../src/types.js";

describe("isValidBanTarget", () => {
  it("accepts valid IPv4 and CIDR", () => {
    expect(isValidBanTarget("1.2.3.4")).toBe(true);
    expect(isValidBanTarget("10.0.0.0/24")).toBe(true);
    expect(isValidBanTarget("2001:db8::1")).toBe(true);
  });
  it("rejects junk and injection attempts", () => {
    expect(isValidBanTarget("1.2.3.4; rm -rf /")).toBe(false);
    expect(isValidBanTarget("not-an-ip")).toBe(false);
    expect(isValidBanTarget("1.2.3.999")).toBe(false);
    expect(isValidBanTarget("10.0.0.0/99")).toBe(false);
    expect(isValidBanTarget("")).toBe(false);
    expect(isValidBanTarget("deny all;")).toBe(false);
  });
});

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "bans-"));
}

function makeService(db: import("../src/store/db.js").DB, customDir: string, exceptions: string[]) {
  const enforcer = new BanEnforcer({
    customDir,
    dockerSocket: "/nonexistent.sock",
    npmContainer: "",
    log: () => {},
  });
  const service = new BanService(
    new BanStore(db),
    enforcer,
    (ip) => ipMatchesAny(ip, exceptions),
  );
  return service;
}

describe("BanService", () => {
  let store: Store;
  let dir: string;

  beforeEach(() => {
    store = new Store(":memory:");
    dir = tmpDir();
  });
  afterEach(() => {
    store.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("bans a valid IP and writes the nginx deny file + include", async () => {
    const svc = makeService(store.db, dir, []);
    const r = await svc.ban("203.0.113.7", { reason: "test", now: 1 });
    expect(r.ok).toBe(true);

    const conf = fs.readFileSync(path.join(dir, "proxylogs-bans.conf"), "utf8");
    expect(conf).toContain("deny 203.0.113.7;");

    const inc = fs.readFileSync(path.join(dir, "server_proxy.conf"), "utf8");
    expect(inc).toContain("/data/nginx/custom/proxylogs-bans.conf");
  });

  it("refuses to ban an excepted IP", async () => {
    const svc = makeService(store.db, dir, ["203.0.113.7"]);
    const r = await svc.ban("203.0.113.7", { now: 1 });
    expect(r.ok).toBe(false);
    expect(svc.list()).toHaveLength(0);
  });

  it("refuses to ban a private address", async () => {
    const svc = makeService(store.db, dir, []);
    const r = await svc.ban("192.168.1.10", { now: 1 });
    expect(r.ok).toBe(false);
  });

  it("rejects an invalid target", async () => {
    const svc = makeService(store.db, dir, []);
    const r = await svc.ban("evil; deny all", { now: 1 });
    expect(r.ok).toBe(false);
  });

  it("unbans and rewrites the file", async () => {
    const svc = makeService(store.db, dir, []);
    await svc.ban("203.0.113.7", { now: 1 });
    await svc.unban("203.0.113.7");
    expect(svc.list()).toHaveLength(0);
    const conf = fs.readFileSync(path.join(dir, "proxylogs-bans.conf"), "utf8");
    expect(conf).not.toContain("203.0.113.7");
  });

  it("reconciles the full list to the file (recovery after a failed write)", async () => {
    // Simulate bans recorded in the DB while the file write was failing.
    const direct = new BanStore(store.db);
    direct.add("203.0.113.10", { now: 1 });
    direct.add("203.0.113.11", { now: 2 });
    expect(fs.existsSync(path.join(dir, "proxylogs-bans.conf"))).toBe(false);

    // A later sync (e.g. on startup or the periodic reconcile) writes them all.
    const svc = makeService(store.db, dir, []);
    await svc.sync();
    const conf = fs.readFileSync(path.join(dir, "proxylogs-bans.conf"), "utf8");
    expect(conf).toContain("deny 203.0.113.10;");
    expect(conf).toContain("deny 203.0.113.11;");
  });

  it("does not rewrite the deny file when the list is unchanged", async () => {
    const svc = makeService(store.db, dir, []);
    await svc.ban("203.0.113.7", { now: 1 });
    const file = path.join(dir, "proxylogs-bans.conf");
    const mtime1 = fs.statSync(file).mtimeMs;
    await new Promise((r) => setTimeout(r, 15));
    await svc.sync(); // same list -> should be a no-op write
    const mtime2 = fs.statSync(file).mtimeMs;
    expect(mtime2).toBe(mtime1);
  });

  it("does not duplicate the include line", async () => {
    const svc = makeService(store.db, dir, []);
    await svc.ban("203.0.113.7", { now: 1 });
    await svc.ban("203.0.113.8", { now: 2 });
    const inc = fs.readFileSync(path.join(dir, "server_proxy.conf"), "utf8");
    const occurrences = inc.split("proxylogs-bans.conf").length - 1;
    expect(occurrences).toBe(1);
  });
});

function entry(over: Partial<AccessEntry>): AccessEntry {
  const NOW = Date.now();
  return {
    hostId: 1, source: "proxy-host-1_access.log", ts: NOW - 60_000, status: 200,
    upstreamStatus: 200, cacheStatus: null, method: "GET", scheme: "https",
    host: "example.com", uri: "/", client: "203.0.113.1", bytes: 100, gzip: null,
    sentTo: "10.0.0.2", userAgent: "Mozilla/5.0", referer: "-", ...over,
  };
}

describe("auto-ban via the engine", () => {
  let store: Store;
  let dir: string;

  beforeEach(() => {
    store = new Store(":memory:");
    dir = tmpDir();
  });
  afterEach(() => {
    store.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("bans an IP that trips enough findings, but not an excepted one", async () => {
    const settings = new Settings(store.db);
    const engine = new ThreatEngine(
      store.db,
      settings,
      new Mailer({ apiKey: "", from: "x@y.z" }),
    );
    const svc = makeService(store.db, dir, ["198.51.100.99"]);
    engine.setBanService(svc);

    const cfg = engine.getConfig();
    cfg.autoBan = { enabled: true, minSeverity: "high", minFindings: 2 };
    engine.setConfig(cfg);

    // Attacker: 404 scan (high) + exploit paths (critical) = 2 distinct rules.
    const attacker = "45.137.21.50";
    const rows: AccessEntry[] = [];
    for (let i = 0; i < 35; i++) rows.push(entry({ status: 404, uri: `/m-${i}`, client: attacker }));
    rows.push(entry({ status: 404, uri: "/.env", client: attacker }));
    rows.push(entry({ status: 404, uri: "/wp-login.php", client: attacker }));
    // Excepted IP doing the same should never be banned.
    for (let i = 0; i < 35; i++) rows.push(entry({ status: 404, uri: `/m-${i}`, client: "198.51.100.99" }));
    rows.push(entry({ status: 404, uri: "/.env", client: "198.51.100.99" }));
    store.insertAccessBatch(rows);

    await engine.evaluate();

    const banned = svc.list().map((b) => b.ip);
    expect(banned).toContain(attacker);
    expect(banned).not.toContain("198.51.100.99");
  });

  it("batches multiple auto-bans into one synced file", async () => {
    const settings = new Settings(store.db);
    const engine = new ThreatEngine(
      store.db,
      settings,
      new Mailer({ apiKey: "", from: "x@y.z" }),
    );
    const svc = makeService(store.db, dir, []);
    engine.setBanService(svc);
    const cfg = engine.getConfig();
    cfg.autoBan = { enabled: true, minSeverity: "high", minFindings: 2 };
    engine.setConfig(cfg);

    const rows: AccessEntry[] = [];
    for (const ip of ["45.137.21.60", "45.137.21.61"]) {
      for (let i = 0; i < 35; i++) rows.push(entry({ status: 404, uri: `/m-${i}`, client: ip }));
      rows.push(entry({ status: 404, uri: "/.env", client: ip }));
    }
    store.insertAccessBatch(rows);
    await engine.evaluate();

    const banned = svc.list().map((b) => b.ip);
    expect(banned).toContain("45.137.21.60");
    expect(banned).toContain("45.137.21.61");
    const conf = fs.readFileSync(path.join(dir, "proxylogs-bans.conf"), "utf8");
    expect(conf).toContain("deny 45.137.21.60;");
    expect(conf).toContain("deny 45.137.21.61;");
  });

  it("does not auto-ban when disabled", async () => {
    const settings = new Settings(store.db);
    const engine = new ThreatEngine(
      store.db,
      settings,
      new Mailer({ apiKey: "", from: "x@y.z" }),
    );
    const svc = makeService(store.db, dir, []);
    engine.setBanService(svc);
    // autoBan defaults to disabled.

    const rows = Array.from({ length: 40 }, (_, i) =>
      entry({ status: 404, uri: `/m-${i}`, client: "45.137.21.51" }),
    );
    store.insertAccessBatch(rows);
    await engine.evaluate();
    expect(svc.list()).toHaveLength(0);
  });
});
