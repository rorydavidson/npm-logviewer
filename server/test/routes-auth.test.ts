import { describe, it, expect, beforeAll, afterAll } from "vitest";
import Fastify, { type FastifyInstance } from "fastify";
import cookie from "@fastify/cookie";
import { registerRoutes, pageParams, type AppCtx } from "../src/api/routes.js";
import { createToken } from "../src/auth/session.js";
import type { Config } from "../src/config.js";

const SECRET = "9f2c1ab4e77d05c3a1b8e6f409d2ccf7";

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
    store: { db: {} },
    bans: { canReload: false, canWrite: false, list: () => [] },
  } as unknown as AppCtx;
}

function validToken(): string {
  return createToken(
    { email: "a@b.c", name: "a", exp: Math.floor(Date.now() / 1000) + 60 },
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
