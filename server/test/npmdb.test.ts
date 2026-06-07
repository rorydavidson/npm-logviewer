import { describe, it, expect, beforeAll, afterAll } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import bcrypt from "bcryptjs";
import { NpmDb } from "../src/npm/npmDb.js";
import { verifyCredentials } from "../src/auth/auth.js";

let dbPath: string;
let npm: NpmDb;

beforeAll(() => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "npmdb-"));
  dbPath = path.join(dir, "database.sqlite");
  const db = new DatabaseSync(dbPath);
  db.exec(`
    CREATE TABLE user (
      id INTEGER PRIMARY KEY, name TEXT, email TEXT,
      is_deleted INTEGER DEFAULT 0, is_disabled INTEGER DEFAULT 0
    );
    CREATE TABLE auth (
      id INTEGER PRIMARY KEY, user_id INTEGER, type TEXT, secret TEXT,
      is_deleted INTEGER DEFAULT 0
    );
    CREATE TABLE proxy_host (
      id INTEGER PRIMARY KEY, domain_names TEXT, forward_host TEXT,
      forward_port INTEGER, enabled INTEGER DEFAULT 1, is_deleted INTEGER DEFAULT 0
    );
  `);

  const hash = bcrypt.hashSync("hunter2", 10);
  db.prepare(`INSERT INTO user (id, name, email) VALUES (1, 'Admin', 'admin@example.com')`).run();
  db.prepare(`INSERT INTO auth (user_id, type, secret) VALUES (1, 'password', ?)`).run(hash);

  // A disabled user that must never authenticate.
  db.prepare(
    `INSERT INTO user (id, name, email, is_disabled) VALUES (2, 'Off', 'off@example.com', 1)`,
  ).run();
  db.prepare(`INSERT INTO auth (user_id, type, secret) VALUES (2, 'password', ?)`).run(hash);

  db.prepare(
    `INSERT INTO proxy_host (id, domain_names, forward_host, forward_port)
     VALUES (1, '["a.example.com","b.example.com"]', 'app', 3000)`,
  ).run();
  db.prepare(
    `INSERT INTO proxy_host (id, domain_names, forward_host, forward_port, is_deleted)
     VALUES (2, '["gone.example.com"]', 'old', 80, 1)`,
  ).run();
  db.close();

  npm = new NpmDb(dbPath);
});

afterAll(() => npm.close());

describe("NpmDb.listProxyHosts", () => {
  it("returns non-deleted hosts with parsed domains", () => {
    const hosts = npm.listProxyHosts();
    expect(hosts).toHaveLength(1);
    expect(hosts[0]?.domainNames).toEqual(["a.example.com", "b.example.com"]);
    expect(hosts[0]?.forwardPort).toBe(3000);
  });
});

describe("NpmDb.findUserByEmail", () => {
  it("finds an active user with their hash", () => {
    const u = npm.findUserByEmail("admin@example.com");
    expect(u?.id).toBe(1);
    expect(u?.passwordHash).toMatch(/^\$2[aby]\$/);
  });
  it("is case-insensitive on email", () => {
    expect(npm.findUserByEmail("ADMIN@EXAMPLE.COM")?.id).toBe(1);
  });
  it("ignores disabled users", () => {
    expect(npm.findUserByEmail("off@example.com")).toBeNull();
  });
});

describe("verifyCredentials", () => {
  it("accepts the correct password", async () => {
    const r = await verifyCredentials(npm, "admin@example.com", "hunter2");
    expect(r.ok).toBe(true);
    expect(r.name).toBe("Admin");
  });
  it("rejects a wrong password", async () => {
    const r = await verifyCredentials(npm, "admin@example.com", "wrong");
    expect(r.ok).toBe(false);
  });
  it("rejects an unknown user", async () => {
    const r = await verifyCredentials(npm, "nobody@example.com", "hunter2");
    expect(r.ok).toBe(false);
  });
  it("rejects a disabled user even with right password", async () => {
    const r = await verifyCredentials(npm, "off@example.com", "hunter2");
    expect(r.ok).toBe(false);
  });
});
