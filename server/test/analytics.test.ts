import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { Store } from "../src/store/store.js";
import * as A from "../src/store/analytics.js";
import type { AccessEntry } from "../src/types.js";

function entry(over: Partial<AccessEntry>): AccessEntry {
  return {
    hostId: 1,
    source: "proxy-host-1_access.log",
    ts: Date.UTC(2024, 0, 1, 12, 0, 0),
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
    userAgent: "UA",
    referer: "-",
    ...over,
  };
}

describe("analytics", () => {
  let store: Store;

  beforeEach(() => {
    store = new Store(":memory:");
    store.insertAccessBatch([
      entry({ status: 200, bytes: 100, uri: "/", client: "203.0.113.1" }),
      entry({ status: 200, bytes: 200, uri: "/a", client: "203.0.113.1" }),
      entry({ status: 404, bytes: 50, uri: "/missing", client: "203.0.113.2" }),
      entry({ status: 500, bytes: 0, uri: "/boom", client: "203.0.113.3", hostId: 2 }),
      entry({ status: 301, bytes: 10, uri: "/old", client: "203.0.113.2", method: "POST" }),
    ]);
  });

  afterEach(() => store.close());

  it("summarises totals and status classes", () => {
    const s = A.getSummary(store.db, {});
    expect(s.requests).toBe(5);
    expect(s.uniqueVisitors).toBe(3);
    expect(s.totalBytes).toBe(360);
    expect(s.class2).toBe(2);
    expect(s.class3).toBe(1);
    expect(s.class4).toBe(1);
    expect(s.class5).toBe(1);
    expect(s.errors).toBe(2);
    expect(s.errorRate).toBeCloseTo(2 / 5);
  });

  it("filters by host id", () => {
    const s = A.getSummary(store.db, { hostId: 2 });
    expect(s.requests).toBe(1);
    expect(s.class5).toBe(1);
  });

  it("filters by status class", () => {
    const s = A.getSummary(store.db, { statusClass: 4 });
    expect(s.requests).toBe(1);
  });

  it("filters by method", () => {
    const s = A.getSummary(store.db, { method: "POST" });
    expect(s.requests).toBe(1);
  });

  it("returns top paths ordered by count", () => {
    const top = A.getTopPaths(store.db, {});
    expect(top[0]?.key).toBeDefined();
    const total = top.reduce((n, r) => n + r.count, 0);
    expect(total).toBe(5);
  });

  it("returns a status breakdown", () => {
    const sb = A.getStatusBreakdown(store.db, {});
    const byStatus = Object.fromEntries(sb.map((r) => [r.status, r.count]));
    expect(byStatus[200]).toBe(2);
    expect(byStatus[404]).toBe(1);
  });

  it("buckets a timeseries", () => {
    const pts = A.getTimeseries(store.db, {}, 3_600_000);
    expect(pts.length).toBe(1);
    expect(pts[0]?.total).toBe(5);
  });

  it("floors timestamps into the correct bucket", () => {
    // Two requests one hour apart must fall into two distinct hourly buckets,
    // and timestamps within the same hour must collapse into one.
    const base = Date.UTC(2024, 5, 1, 9, 0, 0);
    const local = new Store(":memory:");
    local.insertAccessBatch([
      entry({ ts: base + 5 * 60_000 }), // 09:05
      entry({ ts: base + 40 * 60_000 }), // 09:40
      entry({ ts: base + 70 * 60_000 }), // 10:10
    ]);
    const pts = A.getTimeseries(local.db, {}, 3_600_000);
    expect(pts.length).toBe(2);
    expect(pts[0]?.bucket).toBe(base); // 09:00 bucket start
    expect(pts[0]?.total).toBe(2);
    expect(pts[1]?.bucket).toBe(base + 3_600_000); // 10:00 bucket start
    expect(pts[1]?.total).toBe(1);
    local.close();
  });

  it("aggregates per host", () => {
    const hosts = A.getPerHost(store.db, {});
    const h2 = hosts.find((h) => h.hostId === 2);
    expect(h2?.requests).toBe(1);
    expect(h2?.errors).toBe(1);
  });

  it("prunes old rows", () => {
    const removed = store.pruneBefore(Date.UTC(2025, 0, 1));
    expect(removed).toBe(5);
    expect(A.getSummary(store.db, {}).requests).toBe(0);
  });
});

describe("pickBucket", () => {
  it("scales the bucket to the range", () => {
    const oneHour = A.pickBucket(0, 3_600_000);
    const oneWeek = A.pickBucket(0, 7 * 86_400_000);
    expect(oneHour).toBeLessThan(oneWeek);
  });
});
