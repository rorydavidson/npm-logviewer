import { describe, it, expect, beforeAll, afterAll } from "vitest";
import Fastify, { type FastifyInstance } from "fastify";
import cookie from "@fastify/cookie";
import { registerRoutes, type AppCtx } from "../src/api/routes.js";
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
    const token = createToken(
      { email: "a@b.c", name: "a", exp: Math.floor(Date.now() / 1000) + 60 },
      SECRET,
    );
    const res = await app.inject({ url: "/api/bans", cookies: { lv_session: token } });
    expect(res.statusCode).toBe(200);
  });

  it("leaves the health check public", async () => {
    const res = await app.inject({ url: "/api/health" });
    expect(res.statusCode).toBe(200);
  });
});
