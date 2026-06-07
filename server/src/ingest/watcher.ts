import fs from "node:fs";
import path from "node:path";
import { EventEmitter } from "node:events";
import chokidar, { type FSWatcher } from "chokidar";
import type { Store } from "../store/store.js";
import {
  isAccessLog,
  isErrorLog,
  parseAccessLine,
  parseErrorLine,
} from "./parser.js";
import type { AccessEntry, ErrorEntry } from "../types.js";

const BUF_LIMIT = 4 * 1024 * 1024; // read at most 4MB per pass per file

/**
 * Watches the NPM logs directory and ingests appended lines into the store.
 *
 * Each file's byte offset and inode are persisted, so:
 *   - restarts resume where we left off (no duplicates, no gaps);
 *   - log rotation (inode change, or file truncated below our offset) is
 *     detected and the new file is read from the start.
 *
 * Emits `access` / `error` events for each freshly parsed entry so the live
 * tail endpoint can stream them.
 */
export class Watcher extends EventEmitter {
  #store: Store;
  #logsDir: string;
  #backfillCutoff: number;
  #watcher: FSWatcher | null = null;
  #reading = new Set<string>();

  constructor(store: Store, logsDir: string, backfillDays: number) {
    super();
    this.#store = store;
    this.#logsDir = logsDir;
    this.#backfillCutoff =
      backfillDays > 0 ? Date.now() - backfillDays * 86_400_000 : 0;
  }

  async start(): Promise<void> {
    // Initial backfill pass over existing files.
    if (fs.existsSync(this.#logsDir)) {
      const files = fs
        .readdirSync(this.#logsDir)
        .filter((f) => isAccessLog(f) || isErrorLog(f))
        .map((f) => path.join(this.#logsDir, f));
      for (const f of files) await this.#ingestFile(f);
    }

    this.#watcher = chokidar.watch(this.#logsDir, {
      ignoreInitial: true,
      awaitWriteFinish: { stabilityThreshold: 200, pollInterval: 50 },
    });
    this.#watcher
      .on("add", (f) => void this.#ingestFile(f))
      .on("change", (f) => void this.#ingestFile(f));
  }

  async stop(): Promise<void> {
    await this.#watcher?.close();
    this.#watcher = null;
  }

  async #ingestFile(file: string): Promise<void> {
    const base = path.basename(file);
    if (!isAccessLog(base) && !isErrorLog(base)) return;
    // Avoid concurrent passes over the same file (chokidar can fire rapidly).
    if (this.#reading.has(file)) return;
    this.#reading.add(file);
    try {
      await this.#readIncremental(file);
    } catch (err) {
      this.emit("ingest-error", { file, err });
    } finally {
      this.#reading.delete(file);
    }
  }

  async #readIncremental(file: string): Promise<void> {
    const base = path.basename(file);
    let stat: fs.Stats;
    try {
      stat = fs.statSync(file);
    } catch {
      return; // file vanished (rotation race)
    }
    if (!stat.isFile()) return;

    const prev = this.#store.getIngestState(base);
    let offset = 0;
    if (prev) {
      const rotated = prev.inode !== stat.ino || stat.size < prev.offset;
      offset = rotated ? 0 : prev.offset;
    }

    // Loop in case the file is larger than BUF_LIMIT.
    while (offset < stat.size) {
      const end = Math.min(stat.size, offset + BUF_LIMIT);
      const fd = fs.openSync(file, "r");
      const length = end - offset;
      const buf = Buffer.allocUnsafe(length);
      try {
        fs.readSync(fd, buf, 0, length, offset);
      } finally {
        fs.closeSync(fd);
      }

      const text = buf.toString("utf8");
      const lastNl = text.lastIndexOf("\n");
      if (lastNl === -1) {
        // No complete line in this chunk yet; wait for more data.
        break;
      }
      const complete = text.slice(0, lastNl);
      const consumedBytes = Buffer.byteLength(complete + "\n", "utf8");
      const lines = complete.split("\n");

      this.#processLines(base, lines);
      offset += consumedBytes;
    }

    this.#store.setIngestState(base, {
      inode: stat.ino,
      offset,
      mtime: stat.mtimeMs,
    });
  }

  #processLines(source: string, lines: string[]): void {
    if (isErrorLog(source)) {
      const entries: ErrorEntry[] = [];
      for (const line of lines) {
        const e = parseErrorLine(line, source);
        if (e && e.ts >= this.#backfillCutoff) entries.push(e);
      }
      if (entries.length) {
        this.#store.insertErrorBatch(entries);
        for (const e of entries) this.emit("error-entry", e);
      }
      return;
    }

    const entries: AccessEntry[] = [];
    for (const line of lines) {
      const e = parseAccessLine(line, source);
      if (e && e.ts >= this.#backfillCutoff) entries.push(e);
    }
    if (entries.length) {
      this.#store.insertAccessBatch(entries);
      for (const e of entries) this.emit("access-entry", e);
    }
  }
}
