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

  it("ignores findings from excepted IPs and purges existing ones", async () => {
    store.insertAccessBatch(
      Array.from({ length: 40 }, (_, i) =>
        entry({ status: 404, uri: `/m-${i}`, client: "203.0.113.50" }),
      ),
    );
    await engine.evaluate();
    expect(engine.listFindings({}).length).toBeGreaterThan(0);

    const cfg = engine.getConfig();
    cfg.exceptions = ["203.0.113.50"];
    engine.setConfig(cfg);
    await engine.evaluate();
    expect(engine.listFindings({})).toHaveLength(0);
  });

  it("supports CIDR ranges in exceptions", async () => {
    store.insertAccessBatch(
      Array.from({ length: 40 }, (_, i) =>
        entry({ status: 404, uri: `/m-${i}`, client: "10.20.30.40" }),
      ),
    );
    const cfg = engine.getConfig();
    cfg.exceptions = ["10.20.30.0/24"];
    engine.setConfig(cfg);
    await engine.evaluate();
    expect(engine.listFindings({})).toHaveLength(0);
  });

  it("never raises findings for Cloudflare edge IPs", async () => {
    // 104.16.0.1 falls in Cloudflare's 104.16.0.0/13 range. If NPM logs the CDN
    // edge instead of the real visitor, that edge IP must not be acted on.
    store.insertAccessBatch(
      Array.from({ length: 40 }, (_, i) =>
        entry({ status: 404, uri: `/m-${i}`, client: "104.16.0.1" }),
      ),
    );
    await engine.evaluate();
    expect(engine.listFindings({})).toHaveLength(0);
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

describe("ThreatEngine email alerts", () => {
  interface Sent {
    to: string;
    subject: string;
    text: string;
    html?: string;
  }

  function setup(siteUrl: string) {
    const store = new Store(":memory:");
    const settings = new Settings(store.db);
    const sent: Sent[] = [];
    const fakeMailer = {
      configured: true,
      send: async (to: string, subject: string, text: string, html?: string) => {
        sent.push({ to, subject, text, html });
        return { ok: true };
      },
    } as unknown as Mailer;
    const engine = new ThreatEngine(store.db, settings, fakeMailer, undefined, siteUrl);
    return { store, settings, engine, sent };
  }

  function scansFromIps(ips: string[]): AccessEntry[] {
    return ips.flatMap((ip) =>
      Array.from({ length: 35 }, (_, i) =>
        entry({ status: 404, uri: `/m-${ip}-${i}`, client: ip }),
      ),
    );
  }

  it("sends when findings reach alertMinFindings, with deep links", async () => {
    const { store, engine, sent } = setup("https://logs.example.com/");
    store.insertAccessBatch(scansFromIps(["198.51.100.30", "198.51.100.31"]));

    const cfg = engine.getConfig();
    cfg.alertEmail = "ops@example.com";
    cfg.alertMinSeverity = "high"; // scanner404 is "high"
    cfg.alertMinFindings = 2;
    engine.setConfig(cfg);

    await engine.evaluate();
    expect(sent).toHaveLength(1);
    expect(sent[0]?.to).toBe("ops@example.com");
    expect(sent[0]?.text).toContain("https://logs.example.com/threats");
    expect(sent[0]?.text).toContain("https://logs.example.com/logs?client=198.51.100.30");
    // Rich HTML body with the finding details and a deep link.
    expect(sent[0]?.html).toContain("<html");
    expect(sent[0]?.html).toContain("ProxyLogs security alert");
    expect(sent[0]?.html).toContain("View matching log entries");
    expect(sent[0]?.html).toContain("198.51.100.30");
    store.close();
  });

  it("does not send when below alertMinFindings", async () => {
    const { store, engine, sent } = setup("https://logs.example.com");
    store.insertAccessBatch(scansFromIps(["198.51.100.40"])); // only one finding

    const cfg = engine.getConfig();
    cfg.alertEmail = "ops@example.com";
    cfg.alertMinSeverity = "high";
    cfg.alertMinFindings = 2; // need two, have one
    engine.setConfig(cfg);

    await engine.evaluate();
    expect(sent).toHaveLength(0);
    store.close();
  });

  it("respects the per-rule cooldown", async () => {
    const { store, engine, sent } = setup("https://logs.example.com");
    store.insertAccessBatch(scansFromIps(["198.51.100.50"]));

    const cfg = engine.getConfig();
    cfg.alertEmail = "ops@example.com";
    cfg.alertMinSeverity = "high";
    cfg.alertMinFindings = 1;
    cfg.cooldownMinutes = 60;
    engine.setConfig(cfg);

    await engine.evaluate();
    await engine.evaluate(); // immediate re-run is within cooldown
    expect(sent).toHaveLength(1);
    store.close();
  });
});
