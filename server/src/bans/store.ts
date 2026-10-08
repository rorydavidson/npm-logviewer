import net from "node:net";
import type { DB } from "../store/db.js";

export interface Ban {
  ip: string;
  reason: string;
  rule: string | null;
  auto: boolean;
  createdTs: number;
}

// net.isIPv6 also accepts zone ids such as "fe80::1%eth0"; nginx does not.
const IPV6_CHARS = /^[0-9a-fA-F:.]+$/;

/**
 * Strictly validate a ban target before it can ever reach the nginx config
 * file. Only well-formed IPv4/IPv6 addresses or CIDR ranges are allowed — this
 * prevents any log-derived string from injecting nginx directives, and keeps
 * out malformed addresses that nginx would refuse to load (which would stop
 * NPM from starting on its next restart).
 */
export function isValidBanTarget(value: string): boolean {
  const s = value.trim();
  if (!s || s.length > 64) return false;
  const [addr = "", mask, extra] = s.split("/");
  if (extra !== undefined) return false;

  let width: number;
  if (net.isIPv4(addr)) width = 32;
  else if (net.isIPv6(addr) && IPV6_CHARS.test(addr)) width = 128;
  else return false;

  if (mask !== undefined) {
    if (!/^\d{1,3}$/.test(mask)) return false;
    if (Number(mask) > width) return false;
  }
  return true;
}

export class BanStore {
  #db: DB;
  #insert;
  #delete;

  constructor(db: DB) {
    this.#db = db;
    this.#insert = db.prepare(`
      INSERT INTO banned_ip (ip, reason, rule, auto, created_ts)
      VALUES (@ip, @reason, @rule, @auto, @createdTs)
      ON CONFLICT(ip) DO UPDATE SET
        reason = excluded.reason, rule = excluded.rule
    `);
    this.#delete = db.prepare(`DELETE FROM banned_ip WHERE ip = ?`);
  }

  /** Add a ban. Returns false if the target is not a valid IP/CIDR. */
  add(ip: string, opts: { reason?: string; rule?: string | null; auto?: boolean; now: number }): boolean {
    if (!isValidBanTarget(ip)) return false;
    this.#insert.run({
      ip: ip.trim(),
      reason: opts.reason ?? "",
      rule: opts.rule ?? null,
      auto: opts.auto ? 1 : 0,
      createdTs: opts.now,
    });
    return true;
  }

  remove(ip: string): void {
    this.#delete.run(ip);
  }

  has(ip: string): boolean {
    return (
      this.#db.prepare(`SELECT 1 FROM banned_ip WHERE ip = ?`).get(ip) !== undefined
    );
  }

  list(): Ban[] {
    const rows = this.#db
      .prepare(
        `SELECT ip, reason, rule, auto, created_ts AS createdTs
           FROM banned_ip ORDER BY created_ts DESC`,
      )
      .all() as unknown as Array<Omit<Ban, "auto"> & { auto: number }>;
    return rows.map((r) => ({ ...r, auto: r.auto === 1 }));
  }

  /** Just the IP/CIDR strings, for building the nginx snippet. */
  ips(): string[] {
    const rows = this.#db
      .prepare(`SELECT ip FROM banned_ip ORDER BY ip`)
      .all() as unknown as Array<{ ip: string }>;
    return rows.map((r) => r.ip);
  }
}
