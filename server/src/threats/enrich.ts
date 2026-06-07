import type { DB } from "../store/db.js";

export interface SubjectGeo {
  country: string | null;
  city: string | null;
}

export interface TargetHost {
  hostId: number | null;
  label: string;
  count: number;
}

/** Country/city for a client IP, from a sample row. */
export function geoForSubject(db: DB, subject: string): SubjectGeo {
  if (subject === "global") return { country: null, city: null };
  const g = db
    .prepare(`SELECT country, city FROM access_log WHERE client = ? LIMIT 1`)
    .get(subject) as unknown as SubjectGeo | undefined;
  return { country: g?.country ?? null, city: g?.city ?? null };
}

/**
 * The proxy hosts a client IP has been hitting (most first), over the day up to
 * `lastTs`. `label` maps a host id to a human name.
 */
export function targetsForSubject(
  db: DB,
  label: (hostId: number | null) => string,
  subject: string,
  lastTs: number,
): TargetHost[] {
  if (subject === "global") return [];
  const from = lastTs - 24 * 60 * 60 * 1000;
  const rows = db
    .prepare(
      `SELECT host_id AS hostId, COUNT(*) AS count
         FROM access_log
        WHERE client = ? AND ts >= ? AND ts <= ?
        GROUP BY host_id
        ORDER BY count DESC
        LIMIT 5`,
    )
    .all(subject, from, lastTs) as unknown as Array<{
    hostId: number | null;
    count: number;
  }>;
  return rows.map((r) => ({ hostId: r.hostId, label: label(r.hostId), count: r.count }));
}
