import type { DB } from "./db.js";

/** Common filter accepted by every analytics query. */
export interface Filter {
  from?: number; // epoch ms inclusive
  to?: number; // epoch ms exclusive
  hostId?: number | null; // null targets fallback logs, undefined = all
  status?: number; // exact status
  statusClass?: 2 | 3 | 4 | 5; // e.g. 4 -> 4xx
  method?: string;
  country?: string;
  client?: string;
  search?: string; // substring on uri
}

type SqlParams = Record<string, string | number | null>;

interface WhereBuilt {
  sql: string;
  params: SqlParams;
}

function buildWhere(f: Filter): WhereBuilt {
  const clauses: string[] = [];
  const params: SqlParams = {};

  if (f.from !== undefined) {
    clauses.push("ts >= @from");
    params.from = f.from;
  }
  if (f.to !== undefined) {
    clauses.push("ts < @to");
    params.to = f.to;
  }
  if (f.hostId !== undefined) {
    if (f.hostId === null) clauses.push("host_id IS NULL");
    else {
      clauses.push("host_id = @hostId");
      params.hostId = f.hostId;
    }
  }
  if (f.status !== undefined) {
    clauses.push("status = @status");
    params.status = f.status;
  }
  if (f.statusClass !== undefined) {
    clauses.push("status >= @scLo AND status < @scHi");
    params.scLo = f.statusClass * 100;
    params.scHi = (f.statusClass + 1) * 100;
  }
  if (f.method) {
    clauses.push("method = @method");
    params.method = f.method;
  }
  if (f.country) {
    clauses.push("country = @country");
    params.country = f.country;
  }
  if (f.client) {
    clauses.push("client = @client");
    params.client = f.client;
  }
  if (f.search) {
    clauses.push("uri LIKE @search");
    params.search = `%${f.search}%`;
  }

  return { sql: clauses.length ? `WHERE ${clauses.join(" AND ")}` : "", params };
}

export interface Summary {
  requests: number;
  uniqueVisitors: number;
  totalBytes: number;
  errors: number; // status >= 400
  errorRate: number; // 0..1
  avgBytes: number;
  class2: number;
  class3: number;
  class4: number;
  class5: number;
}

export function getSummary(db: DB, f: Filter): Summary {
  const w = buildWhere(f);
  const row = db
    .prepare(
      `SELECT
         COUNT(*)                                            AS requests,
         COUNT(DISTINCT client)                              AS uniqueVisitors,
         COALESCE(SUM(bytes), 0)                             AS totalBytes,
         COALESCE(AVG(bytes), 0)                             AS avgBytes,
         SUM(CASE WHEN status >= 200 AND status < 300 THEN 1 ELSE 0 END) AS class2,
         SUM(CASE WHEN status >= 300 AND status < 400 THEN 1 ELSE 0 END) AS class3,
         SUM(CASE WHEN status >= 400 AND status < 500 THEN 1 ELSE 0 END) AS class4,
         SUM(CASE WHEN status >= 500 THEN 1 ELSE 0 END)      AS class5
       FROM access_log ${w.sql}`,
    )
    .get(w.params) as unknown as Omit<Summary, "errors" | "errorRate"> & {
    class4: number;
    class5: number;
  };

  const errors = (row.class4 ?? 0) + (row.class5 ?? 0);
  return {
    ...row,
    errors,
    errorRate: row.requests ? errors / row.requests : 0,
  };
}

export interface TimePoint {
  bucket: number; // epoch ms (bucket start)
  total: number;
  class2: number;
  class3: number;
  class4: number;
  class5: number;
  bytes: number;
}

/** Choose a sensible bucket size (ms) for a time range. */
export function pickBucket(from: number, to: number): number {
  const span = Math.max(1, to - from);
  const target = 120; // aim for ~120 points
  const raw = span / target;
  const steps = [
    60_000, 5 * 60_000, 15 * 60_000, 30 * 60_000, 3_600_000,
    6 * 3_600_000, 12 * 3_600_000, 86_400_000, 7 * 86_400_000,
  ];
  return steps.find((s) => s >= raw) ?? steps[steps.length - 1]!;
}

export function getTimeseries(db: DB, f: Filter, bucketMs: number): TimePoint[] {
  const w = buildWhere(f);
  const rows = db
    .prepare(
      `SELECT
         (CAST(ts / @bucket AS INTEGER)) * @bucket AS bucket,
         COUNT(*)                 AS total,
         SUM(CASE WHEN status >= 200 AND status < 300 THEN 1 ELSE 0 END) AS class2,
         SUM(CASE WHEN status >= 300 AND status < 400 THEN 1 ELSE 0 END) AS class3,
         SUM(CASE WHEN status >= 400 AND status < 500 THEN 1 ELSE 0 END) AS class4,
         SUM(CASE WHEN status >= 500 THEN 1 ELSE 0 END) AS class5,
         COALESCE(SUM(bytes), 0)  AS bytes
       FROM access_log ${w.sql}
       GROUP BY bucket
       ORDER BY bucket ASC`,
    )
    .all({ ...w.params, bucket: bucketMs }) as unknown as TimePoint[];
  return rows;
}

export interface Bucketed {
  key: string;
  count: number;
  bytes?: number;
}

function topBy(
  db: DB,
  f: Filter,
  column: string,
  limit: number,
  withBytes = false,
): Bucketed[] {
  const w = buildWhere(f);
  const extra = withBytes ? ", COALESCE(SUM(bytes),0) AS bytes" : "";
  const notNull = w.sql ? `${w.sql} AND ${column} IS NOT NULL AND ${column} != ''`
                        : `WHERE ${column} IS NOT NULL AND ${column} != ''`;
  return db
    .prepare(
      `SELECT ${column} AS key, COUNT(*) AS count${extra}
         FROM access_log ${notNull}
         GROUP BY ${column}
         ORDER BY count DESC
         LIMIT @limit`,
    )
    .all({ ...w.params, limit }) as unknown as Bucketed[];
}

export const getTopPaths = (db: DB, f: Filter, limit = 20) =>
  topBy(db, f, "uri", limit, true);
export const getTopClients = (db: DB, f: Filter, limit = 20) =>
  topBy(db, f, "client", limit, true);
export const getTopReferers = (db: DB, f: Filter, limit = 20) =>
  topBy(db, f, "referer", limit);
export const getTopUserAgents = (db: DB, f: Filter, limit = 20) =>
  topBy(db, f, "user_agent", limit);
export const getMethods = (db: DB, f: Filter) => topBy(db, f, "method", 20);

export interface StatusCount {
  status: number;
  count: number;
}
export function getStatusBreakdown(db: DB, f: Filter): StatusCount[] {
  const w = buildWhere(f);
  return db
    .prepare(
      `SELECT status, COUNT(*) AS count
         FROM access_log ${w.sql}
         GROUP BY status ORDER BY count DESC`,
    )
    .all(w.params) as unknown as StatusCount[];
}

export interface CountryStat {
  country: string;
  count: number;
  lat: number | null;
  lon: number | null;
  uniqueVisitors: number;
}
export function getGeo(db: DB, f: Filter, limit = 250): CountryStat[] {
  const w = buildWhere(f);
  const where = w.sql
    ? `${w.sql} AND country IS NOT NULL`
    : `WHERE country IS NOT NULL`;
  return db
    .prepare(
      `SELECT country,
              COUNT(*)               AS count,
              COUNT(DISTINCT client) AS uniqueVisitors,
              AVG(lat)               AS lat,
              AVG(lon)               AS lon
         FROM access_log ${where}
         GROUP BY country
         ORDER BY count DESC
         LIMIT @limit`,
    )
    .all({ ...w.params, limit }) as unknown as CountryStat[];
}

export interface HostStat {
  hostId: number | null;
  requests: number;
  errors: number;
  bytes: number;
  uniqueVisitors: number;
}
export function getPerHost(db: DB, f: Filter): HostStat[] {
  const w = buildWhere(f);
  return db
    .prepare(
      `SELECT host_id AS hostId,
              COUNT(*) AS requests,
              SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END) AS errors,
              COALESCE(SUM(bytes),0) AS bytes,
              COUNT(DISTINCT client) AS uniqueVisitors
         FROM access_log ${w.sql}
         GROUP BY host_id
         ORDER BY requests DESC`,
    )
    .all(w.params) as unknown as HostStat[];
}

export interface AccessRow {
  id: number;
  hostId: number | null;
  ts: number;
  status: number;
  method: string;
  host: string;
  uri: string;
  client: string;
  bytes: number;
  country: string | null;
  city: string | null;
  userAgent: string;
  referer: string;
}

export interface PagedAccess {
  rows: AccessRow[];
  total: number;
}

export function queryAccess(
  db: DB,
  f: Filter,
  limit: number,
  offset: number,
): PagedAccess {
  const w = buildWhere(f);
  const total = (
    db.prepare(`SELECT COUNT(*) AS n FROM access_log ${w.sql}`).get(w.params) as unknown as {
      n: number;
    }
  ).n;
  const rows = db
    .prepare(
      `SELECT id, host_id AS hostId, ts, status, method, host, uri, client,
              bytes, country, city, user_agent AS userAgent, referer
         FROM access_log ${w.sql}
         ORDER BY ts DESC
         LIMIT @limit OFFSET @offset`,
    )
    .all({ ...w.params, limit, offset }) as unknown as AccessRow[];
  return { rows, total };
}

export interface ErrorRow {
  id: number;
  hostId: number | null;
  ts: number;
  level: string;
  message: string;
  client: string | null;
  request: string | null;
  upstream: string | null;
}

export function queryErrors(
  db: DB,
  f: Pick<Filter, "from" | "to" | "hostId">,
  limit: number,
  offset: number,
): { rows: ErrorRow[]; total: number } {
  const clauses: string[] = [];
  const params: SqlParams = {};
  if (f.from !== undefined) { clauses.push("ts >= @from"); params.from = f.from; }
  if (f.to !== undefined) { clauses.push("ts < @to"); params.to = f.to; }
  if (f.hostId !== undefined) {
    if (f.hostId === null) clauses.push("host_id IS NULL");
    else { clauses.push("host_id = @hostId"); params.hostId = f.hostId; }
  }
  const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
  const total = (
    db.prepare(`SELECT COUNT(*) AS n FROM error_log ${where}`).get(params) as unknown as {
      n: number;
    }
  ).n;
  const rows = db
    .prepare(
      `SELECT id, host_id AS hostId, ts, level, message, client, request, upstream
         FROM error_log ${where}
         ORDER BY ts DESC
         LIMIT @limit OFFSET @offset`,
    )
    .all({ ...params, limit, offset }) as unknown as ErrorRow[];
  return { rows, total };
}

/** Overall earliest/latest timestamps in the store, for default ranges. */
export function getBounds(db: DB): { min: number | null; max: number | null } {
  const r = db
    .prepare(`SELECT MIN(ts) AS min, MAX(ts) AS max FROM access_log`)
    .get() as unknown as { min: number | null; max: number | null };
  return r;
}
