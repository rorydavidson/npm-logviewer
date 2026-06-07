import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { Store } from "../src/store/store.js";
import { Settings } from "../src/store/settings.js";
import { Mailer } from "../src/threats/mailer.js";
import { ThreatEngine } from "../src/threats/engine.js";
import { DETECTOR_BY_ID, defaultConfig } from "../src/threats/detectors.js";
import type { AccessEntry } from "../src/types.js";

const NOW = Date.now();

function entry(over: Partial<AccessEntry>): AccessEntry {
  return {
    hostId: 1,
    source: "proxy-host-1_access.log",
    ts: NOW - 60_000, // 1 min ago, inside the default 10-min window
    status: 200,
    upstreamStatus: 200,
    cacheStatus: null,
    method: "GET",
    scheme: "https",
    host: "example.com",
    uri: "/",
    client: "203.0.113.1",
    bytes: 100,
    gzip: null,
    sentTo: "10.0.0.2",
    userAgent: "Mozilla/5.0",
    referer: "-",
    ...over,
  };
}

describe("detectors", () => {
  let store: Store;
  const cfg = defaultConfig();

  beforeEach(() => {
    store = new Store(":memory:");
  });
  afterEach(() => store.close());

  const from = NOW - 10 * 60_000;
  const to = NOW + 1000;

  it("scanner404: flags an IP with many 404s", () => {
    const rows: AccessEntry[] = [];
    for (let i = 0; i < 35; i++) {
      rows.push(entry({ status: 404, uri: `/missing-${i}`, client: "198.51.100.9" }));
    }
    store.insertAccessBatch(rows);
    const f = DETECTOR_BY_ID.get("scanner404")!.run(store.db, from, to, cfg.rules.scanner404!);
    expect(f).toHaveLength(1);
    expect(f[0]?.subject).toBe("198.51.100.9");
    expect(f[0]?.count).toBe(35);
  });

  it("badPaths: flags known exploit paths", () => {
    store.insertAccessBatch([
      entry({ uri: "/.env", client: "198.51.100.10", status: 404 }),
      entry({ uri: "/wp-login.php", client: "198.51.100.10", status: 404 }),
    ]);
    const f = DETECTOR_BY_ID.get("badPaths")!.run(store.db, from, to, cfg.rules.badPaths!);
    expect(f[0]?.subject).toBe("198.51.100.10");
    expect(f[0]?.count).toBe(2);
  });

  it("injection: flags SQLi/XSS signatures", () => {
    store.insertAccessBatch([
      entry({ uri: "/search?q=1 UNION SELECT password FROM users", client: "198.51.100.11" }),
      entry({ uri: "/x?p=../../etc/passwd", client: "198.51.100.11" }),
    ]);
    const f = DETECTOR_BY_ID.get("injection")!.run(store.db, from, to, cfg.rules.injection!);
    expect(f[0]?.subject).toBe("198.51.100.11");
    expect(f[0]?.count).toBe(2);
  });

  it("badAgents: flags scanning tools", () => {
    store.insertAccessBatch([
      entry({ userAgent: "sqlmap/1.7", client: "198.51.100.12" }),
    ]);
    const f = DETECTOR_BY_ID.get("badAgents")!.run(store.db, from, to, cfg.rules.badAgents!);
    expect(f[0]?.subject).toBe("198.51.100.12");
  });

  it("hostScan: flags one IP hitting many hosts", () => {
    const rows: AccessEntry[] = [];
    for (let i = 0; i < 6; i++) {
      rows.push(entry({ host: `site-${i}.example.com`, client: "198.51.100.13" }));
    }
    store.insertAccessBatch(rows);
    const f = DETECTOR_BY_ID.get("hostScan")!.run(store.db, from, to, cfg.rules.hostScan!);
    expect(f[0]?.subject).toBe("198.51.100.13");
    expect(f[0]?.count).toBe(6);
  });

  it("does not fire below threshold", () => {
    store.insertAccessBatch([entry({ status: 404, client: "198.51.100.14" })]);
    const f = DETECTOR_BY_ID.get("scanner404")!.run(store.db, from, to, cfg.rules.scanner404!);
    expect(f).toHaveLength(0);
  });
});

describe("ThreatEngine", () => {
  let store: Store;
  let engine: ThreatEngine;

  beforeEach(() => {
    store = new Store(":memory:");
    const settings = new Settings(store.db);
    const mailer = new Mailer({ apiKey: "", from: "x@y.z" }); // not configured: no send
    engine = new ThreatEngine(store.db, settings, mailer);
  });
  afterEach(() => store.close());

  it("persists findings and dedupes by (rule, subject)", async () => {
    const rows: AccessEntry[] = [];
    for (let i = 0; i < 40; i++) {
      rows.push(entry({ status: 404, uri: `/m-${i}`, client: "198.51.100.20" }));
    }
    store.insertAccessBatch(rows);

    await engine.evaluate();
    await engine.evaluate(); // second pass must update, not duplicate

    const findings = engine.listFindings({ rule: "scanner404" });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.subject).toBe("198.51.100.20");
    expect(findings[0]?.count).toBe(40);

    const counts = engine.counts();
    expect(counts.high).toBeGreaterThanOrEqual(1);
  });

  it("acknowledges findings", async () => {
    store.insertAccessBatch(
      Array.from({ length: 40 }, (_, i) =>
        entry({ status: 404, uri: `/m-${i}`, client: "198.51.100.21" }),
      ),
    );
    await engine.evaluate();
    const before = engine.listFindings({});
    expect(before.length).toBeGreaterThan(0);
    engine.acknowledgeAll();
    expect(engine.listFindings({})).toHaveLength(0);
    expect(engine.listFindings({ includeAcked: true }).length).toBeGreaterThan(0);
  });

  it("merges saved config over defaults", () => {
    const cfg = engine.getConfig();
    cfg.rules.scanner404!.threshold = 999;
    engine.setConfig(cfg);
    expect(engine.getConfig().rules.scanner404?.threshold).toBe(999);
    // A detector added later would still appear via defaults merge.
    expect(engine.getConfig().rules.injection).toBeDefined();
  });
});
