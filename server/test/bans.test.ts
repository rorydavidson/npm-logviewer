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

  it("widens a bare IPv6 ban to its /64 and unbans it the same way", async () => {
    const svc = makeService(store.db, dir, []);
    const r = await svc.ban("2a00:23c5:1234:5678:abcd::1", { reason: "test", now: 1 });
    expect(r.ok).toBe(true);
    expect(svc.list().map((b) => b.ip)).toEqual(["2a00:23c5:1234:5678::/64"]);
    const conf = fs.readFileSync(path.join(dir, "proxylogs-bans.conf"), "utf8");
    expect(conf).toContain("deny 2a00:23c5:1234:5678::/64;");

    // Unbanning any address in the prefix removes the /64 entry.
    await svc.unban("2a00:23c5:1234:5678:ffff::9");
    expect(svc.list()).toHaveLength(0);
  });

  it("refuses to ban an IP inside a trusted IPv6 range", async () => {
    const svc = makeService(store.db, dir, ["2a00:23c5:1234::/48"]);
    const r = await svc.ban("2a00:23c5:1234:5678::1", { now: 1 });
    expect(r.ok).toBe(false);
    expect(svc.list()).toHaveLength(0);
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
    cfg.autoBan = { enabled: true, minSeverity: "high", minFindings: 2, minScore: 12 };
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
    cfg.autoBan = { enabled: true, minSeverity: "high", minFindings: 2, minScore: 12 };
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

  function makeEngine(svc: BanService): ThreatEngine {
    const engine = new ThreatEngine(
      store.db,
      new Settings(store.db),
      new Mailer({ apiKey: "", from: "x@y.z" }),
    );
    engine.setBanService(svc);
    return engine;
  }

  it("groups rotating IPv6 addresses by /64 and bans the prefix", async () => {
    const svc = makeService(store.db, dir, []);
    const engine = makeEngine(svc);
    const cfg = engine.getConfig();
    cfg.autoBan = { enabled: true, minSeverity: "high", minFindings: 2, minScore: 12 };
    engine.setConfig(cfg);

    // Two privacy addresses in the same /64, each tripping a different rule.
    // Individually neither reaches minFindings; as one actor they do.
    const a = "2a00:23c5:1234:5678:aaaa::1";
    const b = "2a00:23c5:1234:5678:bbbb::2";
    const rows: AccessEntry[] = [];
    for (let i = 0; i < 35; i++) rows.push(entry({ status: 404, uri: `/m-${i}`, client: a }));
    rows.push(entry({ status: 404, uri: "/.env", client: b }));
    store.insertAccessBatch(rows);

    await engine.evaluate();

    const banned = svc.list().map((x) => x.ip);
    expect(banned).toContain("2a00:23c5:1234:5678::/64");
    // Re-running must not duplicate the ban (members covered by the /64).
    await engine.evaluate();
    expect(svc.list()).toHaveLength(1);
  });

  it("does not ban a trusted IPv6 prefix, whatever address rotates in", async () => {
    const svc = makeService(store.db, dir, ["2a00:23c5:1234::/48"]);
    const engine = makeEngine(svc);
    const cfg = engine.getConfig();
    cfg.autoBan = { enabled: true, minSeverity: "high", minFindings: 1, minScore: 1 };
    cfg.exceptions = ["2a00:23c5:1234::/48"];
    engine.setConfig(cfg);

    const rows: AccessEntry[] = [];
    for (let i = 0; i < 35; i++) {
      rows.push(entry({ status: 404, uri: `/m-${i}`, client: "2a00:23c5:1234:5678:cccc::9" }));
    }
    rows.push(entry({ status: 404, uri: "/.env", client: "2a00:23c5:1234:5678:dddd::3" }));
    store.insertAccessBatch(rows);

    await engine.evaluate();
    expect(svc.list()).toHaveLength(0);
    expect(engine.listFindings({})).toHaveLength(0);
  });

  it("does not ban when the combined score is below minScore", async () => {
    const svc = makeService(store.db, dir, []);
    const engine = makeEngine(svc);
    const cfg = engine.getConfig();
    cfg.autoBan = { enabled: true, minSeverity: "high", minFindings: 2, minScore: 12 };
    engine.setConfig(cfg);

    // badAgents (high, weight 6) + methodAnomaly (medium, weight 3) = 9 < 12.
    const ip = "45.137.21.70";
    store.insertAccessBatch([
      entry({ userAgent: "", client: ip }),
      entry({ method: "TRACE", client: ip }),
    ]);

    await engine.evaluate();
    expect(svc.list()).toHaveLength(0);
  });

  it("spares a client with an established history of successful traffic", async () => {
    const svc = makeService(store.db, dir, []);
    const engine = makeEngine(svc);
    const cfg = engine.getConfig();
    cfg.autoBan = { enabled: true, minSeverity: "high", minFindings: 2, minScore: 12 };
    engine.setConfig(cfg);

    const homeDevice = "2a00:23c5:9999:1:aaaa::1";
    const rows: AccessEntry[] = [];
    // 40 successful requests two hours ago — a normal device on your network.
    for (let i = 0; i < 40; i++) {
      rows.push(entry({ ts: Date.now() - 2 * 3600_000, status: 200, client: homeDevice }));
    }
    // Now it misbehaves enough to cross the ban bar (expired app token etc.).
    for (let i = 0; i < 35; i++) {
      rows.push(entry({ status: 404, uri: `/m-${i}`, client: homeDevice }));
    }
    rows.push(entry({ status: 404, uri: "/.env", client: homeDevice }));
    store.insertAccessBatch(rows);

    await engine.evaluate();
    expect(svc.list()).toHaveLength(0);
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
