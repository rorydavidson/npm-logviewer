import { describe, it, expect, beforeAll, afterAll } from "vitest";
import Fastify, { type FastifyInstance } from "fastify";
import cookie from "@fastify/cookie";
import { registerRoutes, pageParams, type AppCtx } from "../src/api/routes.js";
import { createToken } from "../src/auth/session.js";
import type { Config } from "../src/config.js";
import { Store } from "../src/store/store.js";

const SECRET = "9f2c1ab4e77d05c3a1b8e6f409d2ccf7";

const activeUsers = new Set(["a@b.c", "gone@b.c"]);

// Only the pieces the routes under test touch; the rest is never called.
function fakeCtx(): AppCtx {
  const config = {
    sessionSecret: SECRET,
    sessionTtlSeconds: 3600,
    secureCookie: false,
    loginMaxAttempts: 10,
    loginWindowMinutes: 15,
  } as Config;
  return {
    config,
    store: new Store(":memory:"),
    npm: { findUserByEmail: (email: string) => (activeUsers.has(email) ? { email } : null) },
    bans: { canReload: false, canWrite: false, list: () => [] },
  } as unknown as AppCtx;
}

function validToken(email = "a@b.c", iat = Date.now()): string {
  return createToken(
    { email, name: "a", exp: Math.floor(Date.now() / 1000) + 60, iat },
    SECRET,
  );
}

describe("API auth gate", () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = Fastify();
    await app.register(cookie);
    await registerRoutes(app, fakeCtx());
    await app.ready();
  });

  afterAll(() => app.close());

  it("rejects an unauthenticated request", async () => {
    const res = await app.inject({ url: "/api/bans" });
    expect(res.statusCode).toBe(401);
  });

  it.each([
    "/%61pi/bans",
    "/%61%70%69/bans",
    "/api/%62ans",
    "/api/bans/",
  ])("rejects the non-canonical path %s", async (url) => {
    const res = await app.inject({ url });
    expect(res.statusCode).not.toBe(200);
  });

  it("allows a request with a valid session", async () => {
    const res = await app.inject({ url: "/api/bans", cookies: { lv_session: validToken() } });
    expect(res.statusCode).toBe(200);
  });

  it("refuses a write sent from a sibling subdomain", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/api/logout",
      cookies: { lv_session: validToken() },
      headers: { "sec-fetch-site": "same-site" },
    });
    expect(res.statusCode).toBe(403);
  });

  it("allows a same-origin write", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/api/logout",
      cookies: { lv_session: validToken() },
      headers: { "sec-fetch-site": "same-origin" },
    });
    expect(res.statusCode).toBe(200);
  });

  it("leaves the health check public", async () => {
    const res = await app.inject({ url: "/api/health" });
    expect(res.statusCode).toBe(200);
  });
});

describe("session revocation", () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = Fastify();
    await app.register(cookie);
    await registerRoutes(app, fakeCtx());
    await app.ready();
  });

  afterAll(() => app.close());

  it("logout ends every existing session for that user", async () => {
    const other = validToken("a@b.c", Date.now() - 1000);
    const mine = validToken("a@b.c", Date.now() - 500);
    expect((await app.inject({ url: "/api/bans", cookies: { lv_session: other } })).statusCode).toBe(200);

    const out = await app.inject({ method: "POST", url: "/api/logout", cookies: { lv_session: mine } });
    expect(out.statusCode).toBe(200);

    // A copy of either token no longer works, but a fresh login does.
    expect((await app.inject({ url: "/api/bans", cookies: { lv_session: mine } })).statusCode).toBe(401);
    expect((await app.inject({ url: "/api/bans", cookies: { lv_session: other } })).statusCode).toBe(401);
    const fresh = validToken("a@b.c", Date.now() + 1);
    expect((await app.inject({ url: "/api/bans", cookies: { lv_session: fresh } })).statusCode).toBe(200);
  });

  it("refuses a session once the NPM user is disabled or deleted", async () => {
    const token = validToken("gone@b.c");
    activeUsers.delete("gone@b.c");
    // A fresh app, so the active-user cache starts empty.
    const fresh = Fastify();
    await fresh.register(cookie);
    await registerRoutes(fresh, fakeCtx());
    const res = await fresh.inject({ url: "/api/bans", cookies: { lv_session: token } });
    expect(res.statusCode).toBe(401);
    await fresh.close();
  });
});

describe("pageParams", () => {
  it("clamps limit to 1..500 so a negative value cannot lift the limit", () => {
    expect(pageParams({ limit: "-1" }).limit).toBe(1);
    expect(pageParams({ limit: "100000" }).limit).toBe(500);
    expect(pageParams({ limit: "2.7" }).limit).toBe(2);
    expect(pageParams({}).limit).toBe(100);
  });

  it("never returns a negative offset", () => {
    expect(pageParams({ offset: "-50" }).offset).toBe(0);
    expect(pageParams({ offset: "abc" }).offset).toBe(0);
  });
});
