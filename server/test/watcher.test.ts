import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Store } from "../src/store/store.js";
import { Watcher } from "../src/ingest/watcher.js";

const LOG = "proxy-host-1_access.log";

function line(uri: string): string {
  return (
    '[10/Oct/2023:13:55:36 +0000] - 200 200 - GET https example.com ' +
    `"${uri}" [Client 203.0.113.5] [Length 12] [Gzip -] [Sent-to 172.18.0.5] ` +
    '"curl/8.0" "-"\n'
  );
}

/** One full ingest pass over the directory, then tear the watcher down. */
async function pass(store: Store, dir: string): Promise<void> {
  const w = new Watcher(store, dir, 0);
  await w.start();
  await w.stop();
}

function uris(store: Store): string[] {
  const rows = store.db
    .prepare(`SELECT uri FROM access_log ORDER BY id`)
    .all() as unknown as Array<{ uri: string }>;
  return rows.map((r) => r.uri);
}

describe("watcher log rotation", () => {
  let dir: string;
  let store: Store;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "logs-"));
    store = new Store(":memory:");
  });

  afterEach(() => {
    store.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("does not re-ingest a file that was renamed by logrotate", async () => {
    fs.writeFileSync(path.join(dir, LOG), line("/a") + line("/b"));
    await pass(store, dir);
    expect(uris(store)).toEqual(["/a", "/b"]);

    // logrotate renames the live file (inode preserved) and nginx opens a new
    // one. The rotated file must not be read again from the start.
    fs.renameSync(path.join(dir, LOG), path.join(dir, `${LOG}.1`));
    fs.writeFileSync(path.join(dir, LOG), line("/c"));
    await pass(store, dir);

    expect(uris(store)).toEqual(["/a", "/b", "/c"]);
  });

  it("still ingests a rotated file it has never seen", async () => {
    // First boot with history already on disk: the .1 file is genuinely new to
    // us, so its contents belong in the store.
    fs.writeFileSync(path.join(dir, `${LOG}.1`), line("/old"));
    fs.writeFileSync(path.join(dir, LOG), line("/new"));
    await pass(store, dir);

    expect(uris(store).sort()).toEqual(["/new", "/old"]);
  });

  it("reads from the start when a file is truncated in place", async () => {
    fs.writeFileSync(path.join(dir, LOG), line("/a") + line("/b"));
    await pass(store, dir);

    // copytruncate-style rotation: same inode, file shrinks below our offset.
    fs.writeFileSync(path.join(dir, LOG), line("/c"));
    await pass(store, dir);

    expect(uris(store)).toEqual(["/a", "/b", "/c"]);
  });

  it("carries filename-keyed state over to the inode-keyed table", async () => {
    const file = path.join(dir, LOG);
    fs.writeFileSync(file, line("/a") + line("/b"));
    const size = fs.statSync(file).size;
    const inode = fs.statSync(file).ino;

    // A store upgraded from the old schema: state keyed on the filename.
    const legacy = new Store(path.join(dir, "state.db"));
    legacy.db
      .prepare(
        `CREATE TABLE ingest_state (
           source TEXT PRIMARY KEY, inode INTEGER NOT NULL,
           offset INTEGER NOT NULL, mtime INTEGER NOT NULL)`,
      )
      .run();
    legacy.db
      .prepare(`INSERT INTO ingest_state VALUES (?, ?, ?, 0)`)
      .run(LOG, inode, size);
    legacy.close();

    const upgraded = new Store(path.join(dir, "state.db"));
    await pass(upgraded, dir);
    // The offset survived the upgrade, so nothing is read a second time.
    expect(uris(upgraded)).toEqual([]);
    upgraded.close();
  });

  it("forgets state for files that have rotated away", async () => {
    fs.writeFileSync(path.join(dir, LOG), line("/a"));
    await pass(store, dir);
    fs.rmSync(path.join(dir, LOG));
    await pass(store, dir);

    const rows = store.db
      .prepare(`SELECT COUNT(*) AS n FROM ingest_offset`)
      .get() as unknown as { n: number };
    expect(rows.n).toBe(0);
  });
});
