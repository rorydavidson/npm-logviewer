import { describe, it, expect } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "../src/store/db.js";
import { Store } from "../src/store/store.js";

/** Create a database with the pre-client_net access_log schema and some rows. */
function makeLegacyDb(file: string): void {
  const db = new DatabaseSync(file);
  db.prepare(`
    CREATE TABLE access_log (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      host_id         INTEGER,
      source          TEXT NOT NULL,
      ts              INTEGER NOT NULL,
      status          INTEGER NOT NULL,
      upstream_status INTEGER,
      cache_status    TEXT,
      method          TEXT NOT NULL,
      scheme          TEXT NOT NULL,
      host            TEXT NOT NULL,
      uri             TEXT NOT NULL,
      client          TEXT NOT NULL,
      bytes           INTEGER NOT NULL DEFAULT 0,
      gzip            REAL,
      sent_to         TEXT,
      user_agent      TEXT NOT NULL DEFAULT '',
      referer         TEXT NOT NULL DEFAULT '',
      country         TEXT,
      region          TEXT,
      city            TEXT,
      lat             REAL,
      lon             REAL
    )
  `).run();
  const ins = db.prepare(`
    INSERT INTO access_log (source, ts, status, method, scheme, host, uri, client)
    VALUES ('legacy.log', 1, 200, 'GET', 'https', 'example.com', '/', ?)
  `);
  ins.run("203.0.113.7");
  ins.run("2a00:23c5:1234:5678:abcd::1");
  ins.run("2a00:23c5:1234:5678:ffff::2"); // same /64, different address
  db.close();
}

describe("client_net migration", () => {
  it("adds the column and backfills existing rows on startup", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "migrate-"));
    const file = path.join(dir, "state.db");
    makeLegacyDb(file);

    // Opening the Store must upgrade the legacy schema without operator action.
    const store = new Store(file);
    const rows = store.db
      .prepare(`SELECT client, client_net FROM access_log ORDER BY id`)
      .all() as unknown as Array<{ client: string; client_net: string }>;

    expect(rows).toHaveLength(3);
    expect(rows[0]?.client_net).toBe("203.0.113.7");
    expect(rows[1]?.client_net).toBe("2a00:23c5:1234:5678::/64");
    expect(rows[2]?.client_net).toBe("2a00:23c5:1234:5678::/64");

    // New inserts get client_net too, and the migration is idempotent.
    store.close();
    const reopened = new Store(file);
    const count = reopened.db
      .prepare(`SELECT COUNT(*) AS n FROM access_log WHERE client_net IS NULL`)
      .get() as unknown as { n: number };
    expect(count.n).toBe(0);
    reopened.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });
});
