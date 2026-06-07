import fs from "node:fs";
import { DatabaseSync, type DB } from "../store/db.js";
import type { NpmUser, ProxyHost } from "../types.js";

/**
 * Read-only access to the Nginx Proxy Manager SQLite database.
 *
 * We open in readonly mode and never write — NPM owns this file. The schema is
 * a hard dependency: if NPM changes these tables, the reads below are the only
 * place that needs updating.
 */
export class NpmDb {
  #db: DB | null = null;
  #path: string;

  constructor(dbPath: string) {
    this.#path = dbPath;
  }

  /** Open lazily; returns null if the DB file does not exist yet. */
  #open(): DB | null {
    if (this.#db) return this.#db;
    if (!fs.existsSync(this.#path)) return null;
    this.#db = new DatabaseSync(this.#path, { readOnly: true });
    return this.#db;
  }

  /** All proxy hosts, keyed for fast id -> name lookups by the caller. */
  listProxyHosts(): ProxyHost[] {
    const db = this.#open();
    if (!db) return [];
    const rows = db
      .prepare(
        `SELECT id, domain_names, forward_host, forward_port, enabled
           FROM proxy_host
          WHERE is_deleted = 0`,
      )
      .all() as unknown as Array<{
      id: number;
      domain_names: string;
      forward_host: string;
      forward_port: number;
      enabled: number;
    }>;

    return rows.map((r) => ({
      id: r.id,
      domainNames: safeJsonArray(r.domain_names),
      forwardHost: r.forward_host,
      forwardPort: r.forward_port,
      enabled: r.enabled === 1,
    }));
  }

  /**
   * Find an active NPM user and their bcrypt password hash by email.
   * Returns null if the user is missing, deleted, or disabled.
   */
  findUserByEmail(email: string): NpmUser | null {
    const db = this.#open();
    if (!db) return null;
    const user = db
      .prepare(
        `SELECT id, name, email FROM user
          WHERE lower(email) = lower(?) AND is_deleted = 0 AND is_disabled = 0`,
      )
      .get(email) as unknown as { id: number; name: string; email: string } | undefined;
    if (!user) return null;

    const auth = db
      .prepare(
        `SELECT secret FROM auth
          WHERE user_id = ? AND type = 'password' AND is_deleted = 0
          LIMIT 1`,
      )
      .get(user.id) as unknown as { secret: string } | undefined;

    return {
      id: user.id,
      name: user.name,
      email: user.email,
      passwordHash: auth?.secret ?? null,
    };
  }

  close(): void {
    this.#db?.close();
    this.#db = null;
  }
}

function safeJsonArray(value: string): string[] {
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed.map(String) : [];
  } catch {
    return [];
  }
}
