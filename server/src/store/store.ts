import fs from "node:fs";
import path from "node:path";
import { DatabaseSync, type DB } from "./db.js";
import { SCHEMA } from "./schema.js";
import { lookupGeo } from "../ingest/geo.js";
import { ipv6Subnet } from "../ingest/networks.js";
import type { AccessEntry, ErrorEntry } from "../types.js";

export interface IngestState {
  inode: number;
  offset: number;
  mtime: number;
}

/**
 * Owns the writable SQLite database that holds parsed log rows. The NPM
 * database is never touched here — only our own state DB.
 */
export class Store {
  readonly db: DB;
  #insertAccess;
  #insertError;
  #getState;
  #setState;

  constructor(dbPath: string) {
    if (dbPath !== ":memory:") {
      fs.mkdirSync(path.dirname(dbPath), { recursive: true });
    }
    this.db = new DatabaseSync(dbPath);
    this.db.exec("PRAGMA journal_mode = WAL");
    this.db.exec("PRAGMA synchronous = NORMAL");
    this.db.exec(SCHEMA);
    this.#migrate();

    this.#insertAccess = this.db.prepare(`
      INSERT INTO access_log
        (host_id, source, ts, status, upstream_status, cache_status, method,
         scheme, host, uri, client, client_net, bytes, gzip, sent_to, user_agent,
         referer, country, region, city, lat, lon)
      VALUES
        (@hostId, @source, @ts, @status, @upstreamStatus, @cacheStatus, @method,
         @scheme, @host, @uri, @client, @clientNet, @bytes, @gzip, @sentTo, @userAgent,
         @referer, @country, @region, @city, @lat, @lon)
    `);

    this.#insertError = this.db.prepare(`
      INSERT INTO error_log
        (host_id, source, ts, level, message, client, server, request, upstream)
      VALUES
        (@hostId, @source, @ts, @level, @message, @client, @server, @request, @upstream)
    `);

    this.#getState = this.db.prepare(
      `SELECT inode, offset, mtime FROM ingest_state WHERE source = ?`,
    );
    this.#setState = this.db.prepare(`
      INSERT INTO ingest_state (source, inode, offset, mtime)
      VALUES (@source, @inode, @offset, @mtime)
      ON CONFLICT(source) DO UPDATE SET
        inode = excluded.inode, offset = excluded.offset, mtime = excluded.mtime
    `);
  }

  /**
   * Bring an existing database up to the current schema. Runs on every start
   * and is a no-op once applied, so upgrades need no operator action.
   */
  #migrate(): void {
    const cols = this.db
      .prepare(`PRAGMA table_info(access_log)`)
      .all() as unknown as Array<{ name: string }>;
    if (!cols.some((c) => c.name === "client_net")) {
      this.db.exec(`ALTER TABLE access_log ADD COLUMN client_net TEXT`);
    }
    // Backfill rows ingested before the column existed.
    const needsBackfill = this.db
      .prepare(`SELECT 1 FROM access_log WHERE client_net IS NULL LIMIT 1`)
      .get();
    if (needsBackfill) {
      this.db.exec("BEGIN");
      try {
        // IPv4 (and anything without a colon) maps to itself — one pass.
        this.db.exec(
          `UPDATE access_log SET client_net = client
            WHERE client_net IS NULL AND client NOT LIKE '%:%'`,
        );
        // IPv6 needs the /64 computed in JS; one update per distinct address.
        const v6 = this.db
          .prepare(`SELECT DISTINCT client FROM access_log WHERE client_net IS NULL`)
          .all() as unknown as Array<{ client: string }>;
        const upd = this.db.prepare(
          `UPDATE access_log SET client_net = ? WHERE client = ? AND client_net IS NULL`,
        );
        for (const { client } of v6) upd.run(ipv6Subnet(client) ?? client, client);
        this.db.exec("COMMIT");
      } catch (err) {
        this.db.exec("ROLLBACK");
        throw err;
      }
    }
    this.db.exec(
      `CREATE INDEX IF NOT EXISTS idx_access_client_net ON access_log (client_net, ts)`,
    );
  }

  insertAccessBatch(entries: AccessEntry[]): void {
    if (entries.length === 0) return;
    this.db.exec("BEGIN");
    try {
      for (const e of entries) {
        const geo = lookupGeo(e.client);
        this.#insertAccess.run({
          hostId: e.hostId,
          source: e.source,
          ts: e.ts,
          status: e.status,
          upstreamStatus: e.upstreamStatus,
          cacheStatus: e.cacheStatus,
          method: e.method,
          scheme: e.scheme,
          host: e.host,
          uri: e.uri,
          client: e.client,
          clientNet: ipv6Subnet(e.client) ?? e.client,
          bytes: e.bytes,
          gzip: e.gzip,
          sentTo: e.sentTo,
          userAgent: e.userAgent,
          referer: e.referer,
          country: geo.country,
          region: geo.region,
          city: geo.city,
          lat: geo.lat,
          lon: geo.lon,
        });
      }
      this.db.exec("COMMIT");
    } catch (err) {
      this.db.exec("ROLLBACK");
      throw err;
    }
  }

  insertErrorBatch(entries: ErrorEntry[]): void {
    if (entries.length === 0) return;
    this.db.exec("BEGIN");
    try {
      for (const e of entries) {
        this.#insertError.run({
          hostId: e.hostId,
          source: e.source,
          ts: e.ts,
          level: e.level,
          message: e.message,
          client: e.client,
          server: e.server,
          request: e.request,
          upstream: e.upstream,
        });
      }
      this.db.exec("COMMIT");
    } catch (err) {
      this.db.exec("ROLLBACK");
      throw err;
    }
  }

  getIngestState(source: string): IngestState | null {
    const row = this.#getState.get(source) as unknown as
      | { inode: number; offset: number; mtime: number }
      | undefined;
    return row ?? null;
  }

  setIngestState(source: string, state: IngestState): void {
    this.#setState.run({ source, ...state });
  }

  /** Delete rows older than the given epoch ms. Used for retention. */
  pruneBefore(cutoffMs: number): number {
    const a = this.db.prepare(`DELETE FROM access_log WHERE ts < ?`).run(cutoffMs);
    const e = this.db.prepare(`DELETE FROM error_log WHERE ts < ?`).run(cutoffMs);
    return Number(a.changes) + Number(e.changes);
  }

  close(): void {
    this.db.close();
  }
}
