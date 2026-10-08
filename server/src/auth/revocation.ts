import type { DB } from "../store/db.js";
import type { NpmDb } from "../npm/npmDb.js";
import type { SessionPayload } from "./session.js";

/**
 * Server-side half of logout. Session tokens are stateless, so clearing the
 * cookie alone leaves a copied token valid until it expires. Logging out
 * records a per-user cut-off; any token issued at or before it is refused,
 * which ends every session that user has, on every device.
 */
export class SessionRevocations {
  #get;
  #set;

  constructor(db: DB) {
    this.#get = db.prepare(
      `SELECT revoked_before AS revokedBefore FROM session_revocation WHERE email = ?`,
    );
    this.#set = db.prepare(`
      INSERT INTO session_revocation (email, revoked_before) VALUES (?, ?)
      ON CONFLICT(email) DO UPDATE SET revoked_before = excluded.revoked_before
    `);
  }

  revokeAll(email: string, now = Date.now()): void {
    this.#set.run(email.toLowerCase(), now);
  }

  isRevoked(session: SessionPayload): boolean {
    const row = this.#get.get(session.email.toLowerCase()) as unknown as
      | { revokedBefore: number }
      | undefined;
    return row !== undefined && (session.iat ?? 0) <= row.revokedBefore;
  }
}

/**
 * Whether the session's NPM user still exists and is enabled, so disabling or
 * deleting a user in NPM ends their dashboard access too. Cached briefly to
 * avoid two NPM queries on every API call.
 */
export function makeActiveUserCheck(npm: NpmDb, ttlMs = 60_000) {
  const cache = new Map<string, { active: boolean; until: number }>();
  return (email: string, now = Date.now()): boolean => {
    const key = email.toLowerCase();
    const hit = cache.get(key);
    if (hit && hit.until > now) return hit.active;
    const active = npm.findUserByEmail(email) !== null;
    cache.set(key, { active, until: now + ttlMs });
    return active;
  };
}
