import type { DB } from "./db.js";

/** Tiny key/value settings store backed by the state database. */
export class Settings {
  #get;
  #set;

  constructor(db: DB) {
    this.#get = db.prepare(`SELECT value FROM app_settings WHERE key = ?`);
    this.#set = db.prepare(`
      INSERT INTO app_settings (key, value) VALUES (@key, @value)
      ON CONFLICT(key) DO UPDATE SET value = excluded.value
    `);
  }

  get(key: string): string | null {
    const row = this.#get.get(key) as unknown as { value: string } | undefined;
    return row?.value ?? null;
  }

  set(key: string, value: string): void {
    this.#set.run({ key, value });
  }

  getJSON<T>(key: string): T | null {
    const raw = this.get(key);
    if (raw === null) return null;
    try {
      return JSON.parse(raw) as T;
    } catch {
      return null;
    }
  }

  setJSON(key: string, value: unknown): void {
    this.set(key, JSON.stringify(value));
  }
}
