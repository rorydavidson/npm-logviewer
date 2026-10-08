import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { Config } from "../config.js";
import type { Store } from "../store/store.js";
import type { NpmDb } from "../npm/npmDb.js";
import type { HostMap } from "../npm/hostMap.js";
import type { Watcher } from "../ingest/watcher.js";
import { verifyCredentials } from "../auth/auth.js";
import { createToken, verifyToken, type SessionPayload } from "../auth/session.js";
import { SessionRevocations, makeActiveUserCheck } from "../auth/revocation.js";
import { parseFilter } from "./filter.js";
import * as A from "../store/analytics.js";
import type { AccessEntry, ErrorEntry } from "../types.js";
import type { ThreatEngine } from "../threats/engine.js";
import type { Mailer } from "../threats/mailer.js";
import type { BanService } from "../bans/service.js";
import { DETECTORS } from "../threats/detectors.js";
import { sanitizeThreatConfig } from "../threats/validate.js";
import { geoForSubject, targetsForSubject } from "../threats/enrich.js";
import { lookupGeo } from "../ingest/geo.js";
import type { Severity } from "../threats/types.js";
import { RateLimiter } from "../security/rateLimit.js";
import { isCrossSiteWrite } from "../security/csrf.js";

const COOKIE = "lv_session";

/** API routes reachable without a session. Matched against route patterns. */
const PUBLIC_ROUTES = new Set(["/api/login", "/api/health"]);

export interface AppCtx {
  config: Config;
  store: Store;
  npm: NpmDb;
  hosts: HostMap;
  watcher: Watcher;
  engine: ThreatEngine;
  mailer: Mailer;
  bans: BanService;
}

function num(v: unknown, fallback: number): number {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

/**
 * Parse limit/offset query params into a safe page. Both are clamped because
 * SQLite treats a negative LIMIT as "no limit", which would return every row.
 */
export function pageParams(q: Record<string, string>): { limit: number; offset: number } {
  const limit = Math.trunc(Math.min(500, Math.max(1, num(q.limit, 100))));
  const offset = Math.trunc(Math.max(0, num(q.offset, 0)));
  return { limit, offset };
}

export async function registerRoutes(app: FastifyInstance, ctx: AppCtx): Promise<void> {
  const { config, store, npm, hosts, watcher, engine, mailer, bans } = ctx;
  const db = store.db;

  const revocations = new SessionRevocations(db);
  const isActiveUser = makeActiveUserCheck(npm);

  /** Signature, expiry, logout and NPM user status; null if any fails. */
  const validSession = (token: string | undefined): SessionPayload | null => {
    const session = verifyToken(token, config.sessionSecret);
    if (!session) return null;
    if (revocations.isRevoked(session)) return null;
    if (!isActiveUser(session.email)) return null;
    return session;
  };

  const loginLimiter = new RateLimiter(
    config.loginMaxAttempts,
    config.loginWindowMinutes * 60_000,
  );

  // --- health check (unauthenticated, for Docker/uptime probes) ------------
  // Deliberately says nothing about the deployment beyond liveness.
  app.get("/api/health", async () => ({ ok: true }));

  // --- CSRF check and auth gate for everything under /api ------------------
  // Decide on the matched route pattern, never the raw URL: the router
  // percent-decodes the path before matching, so "/%61pi/threats" reaches the
  // /api/threats handler while its raw URL does not start with "/api/".
  app.addHook("preHandler", async (req: FastifyRequest, reply: FastifyReply) => {
    const route = req.routeOptions.url;
    // No matched route means the not-found handler, which serves no data.
    if (!route || !route.startsWith("/api/")) return;
    if (isCrossSiteWrite(req.method, req.headers)) {
      reply.code(403).send({ error: "cross-site request refused" });
      return reply;
    }
    if (PUBLIC_ROUTES.has(route)) return;
    const session = validSession(req.cookies?.[COOKIE]);
    if (!session) {
      reply.code(401).send({ error: "unauthorised" });
      return reply;
    }
    (req as FastifyRequest & { session: SessionPayload }).session = session;
  });

  // --- auth ----------------------------------------------------------------
  app.post("/api/login", async (req, reply) => {
    const ip = req.ip || "unknown";
    if (loginLimiter.isLimited(ip)) {
      return reply
        .code(429)
        .send({ error: "too many login attempts, try again later" });
    }

    // The body is untrusted JSON: a non-string here used to reach the SQLite
    // bind and bcrypt and surface as a 500.
    const { email, password } = (req.body ?? {}) as Record<string, unknown>;
    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      !email ||
      !password ||
      email.length > 320 ||
      password.length > 1024
    ) {
      return reply.code(400).send({ error: "email and password required" });
    }
    const result = await verifyCredentials(npm, email, password);
    if (!result.ok) {
      loginLimiter.record(ip);
      return reply.code(401).send({ error: "invalid credentials" });
    }
    loginLimiter.reset(ip);

    const exp = Math.floor(Date.now() / 1000) + config.sessionTtlSeconds;
    const token = createToken(
      { email: result.email!, name: result.name ?? result.email!, exp, iat: Date.now() },
      config.sessionSecret,
    );
    reply.setCookie(COOKIE, token, {
      httpOnly: true,
      // Strict: the SPA's own API calls are always same-site, and nothing
      // needs the cookie on a cross-site navigation into the dashboard.
      sameSite: "strict",
      secure: config.secureCookie,
      path: "/",
      maxAge: config.sessionTtlSeconds,
    });
    return { ok: true, name: result.name, email: result.email };
  });

  app.post("/api/logout", async (req, reply) => {
    const s = (req as FastifyRequest & { session: SessionPayload }).session;
    revocations.revokeAll(s.email);
    reply.clearCookie(COOKIE, { path: "/" });
    return { ok: true };
  });

  app.get("/api/me", async (req) => {
    const s = (req as FastifyRequest & { session: SessionPayload }).session;
    return { email: s.email, name: s.name };
  });

  // --- metadata for filters ------------------------------------------------
  app.get("/api/meta", async () => {
    const bounds = A.getBounds(db);
    return {
      bounds,
      hosts: hosts.all().map((h) => ({
        id: h.id,
        label: h.domainNames[0] ?? `host-${h.id}`,
        domainNames: h.domainNames,
        enabled: h.enabled,
        forward: `${h.forwardHost}:${h.forwardPort}`,
      })),
    };
  });

  // --- the big overview bundle --------------------------------------------
  app.get("/api/overview", async (req) => {
    const f = parseFilter(req.query as Record<string, string>);
    const bucket = A.pickBucket(f.from ?? 0, f.to ?? Date.now());
    const perHost = A.getPerHost(db, f).map((h) => ({
      ...h,
      label: hosts.label(h.hostId),
    }));
    return {
      filter: f,
      bucketMs: bucket,
      summary: A.getSummary(db, f),
      timeseries: A.getTimeseries(db, f, bucket),
      statusBreakdown: A.getStatusBreakdown(db, f),
      methods: A.getMethods(db, f),
      topPaths: A.getTopPaths(db, f),
      topClients: A.getTopClients(db, f).map(withGeo(db, f)),
      topReferers: A.getTopReferers(db, f),
      topUserAgents: A.getTopUserAgents(db, f),
      geo: A.getGeo(db, f),
      perHost,
      bannedClients: A.getTopClients(db, f)
        .map((c) => c.key)
        .filter(bans.checker()),
    };
  });

  app.get("/api/timeseries", async (req) => {
    const f = parseFilter(req.query as Record<string, string>);
    const bucket = A.pickBucket(f.from ?? 0, f.to ?? Date.now());
    return { bucketMs: bucket, points: A.getTimeseries(db, f, bucket) };
  });

  app.get("/api/geo", async (req) => {
    const f = parseFilter(req.query as Record<string, string>);
    return { countries: A.getGeo(db, f) };
  });

  app.get("/api/hosts", async (req) => {
    const f = parseFilter(req.query as Record<string, string>);
    return {
      hosts: A.getPerHost(db, f).map((h) => ({
        ...h,
        label: hosts.label(h.hostId),
      })),
    };
  });

  // --- paginated raw access rows ------------------------------------------
  app.get("/api/logs", async (req) => {
    const q = req.query as Record<string, string>;
    const f = parseFilter(q);
    const { limit, offset } = pageParams(q);
    const page = A.queryAccess(db, f, limit, offset);
    const isBanned = bans.checker();
    return {
      total: page.total,
      limit,
      offset,
      rows: page.rows.map((r) => ({
        ...r,
        hostLabel: hosts.label(r.hostId),
        banned: isBanned(r.client),
      })),
    };
  });

  app.get("/api/errors", async (req) => {
    const q = req.query as Record<string, string>;
    const f = parseFilter(q);
    const { limit, offset } = pageParams(q);
    const page = A.queryErrors(db, f, limit, offset);
    return {
      total: page.total,
      limit,
      offset,
      rows: page.rows.map((r) => ({ ...r, hostLabel: hosts.label(r.hostId) })),
    };
  });

  // --- threat detection ----------------------------------------------------
  app.get("/api/threats", async (req) => {
    const q = req.query as Record<string, string>;
    const findings = engine.listFindings({
      minSeverity: (q.severity as Severity) || undefined,
      rule: q.rule || undefined,
      includeAcked: q.acked === "1",
    });
    const isBanned = bans.checker();
    return {
      counts: engine.counts(),
      findings: findings.map((f) => ({
        ...f,
        // For IP subjects, attach geo so the UI can show a flag.
        ...geoForSubject(db, f.subject),
        // Which proxy hosts this subject has been hitting.
        targets: targetsForSubject(db, (id) => hosts.label(id), f.subject, f.lastTs),
        banned: f.subject !== "global" && isBanned(f.subject),
      })),
    };
  });

  app.post("/api/threats/ack", async (req, reply) => {
    const { id } = (req.body ?? {}) as { id?: number };
    if (typeof id !== "number") return reply.code(400).send({ error: "id required" });
    engine.acknowledge(id);
    return { ok: true };
  });

  app.post("/api/threats/ack-all", async () => {
    engine.acknowledgeAll();
    return { ok: true };
  });

  app.post("/api/threats/clear", async () => {
    engine.clear();
    return { ok: true };
  });

  app.get("/api/threats/config", async () => ({
    config: engine.getConfig(),
    emailConfigured: mailer.configured,
    detectors: DETECTORS.map((d) => ({
      id: d.id,
      title: d.title,
      description: d.description,
      editable: d.editable,
    })),
  }));

  app.put("/api/threats/config", async (req, reply) => {
    if (!req.body || typeof req.body !== "object") {
      return reply.code(400).send({ error: "invalid config" });
    }
    // Coerce/clamp untrusted input into a safe, well-formed config.
    const clean = sanitizeThreatConfig(req.body);
    engine.setConfig(clean);
    // Re-evaluate immediately so the UI reflects the new rules.
    void engine.evaluate();
    return { ok: true, config: clean };
  });

  app.post("/api/threats/run", async () => {
    await engine.evaluate();
    return { ok: true };
  });

  // --- ban list ------------------------------------------------------------
  app.get("/api/bans", async () => ({
    canReload: bans.canReload,
    canWrite: bans.canWrite,
    bans: bans.list().map((b) => ({ ...b, ...geoForSubject(db, b.ip) })),
  }));

  app.post("/api/bans", async (req, reply) => {
    const { ip, reason } = (req.body ?? {}) as { ip?: string; reason?: string };
    if (!ip || typeof ip !== "string") {
      return reply.code(400).send({ error: "ip required" });
    }
    const result = await bans.ban(ip, {
      reason: typeof reason === "string" ? reason.slice(0, 200) : "manual",
      auto: false,
      now: Date.now(),
    });
    if (!result.ok) return reply.code(400).send({ error: result.reason });
    return { ok: true };
  });

  app.delete("/api/bans/:ip", async (req) => {
    const { ip } = req.params as { ip: string };
    await bans.unban(ip);
    return { ok: true };
  });

  // Re-write the nginx deny file from the full list (e.g. after fixing perms).
  app.post("/api/bans/sync", async () => {
    await bans.sync();
    return { ok: true, canWrite: bans.canWrite, canReload: bans.canReload };
  });

  app.post("/api/threats/test-email", async () => {
    const cfg = engine.getConfig();
    if (!cfg.alertEmail) return { ok: false, error: "set an alert email first" };
    const result = await mailer.send(
      cfg.alertEmail,
      "[ProxyLogs] Test alert",
      "This is a test alert from ProxyLogs. If you received it, email alerts are working.",
    );
    return result;
  });

  // --- live tail via Server-Sent Events -----------------------------------
  app.get("/api/stream", async (req, reply) => {
    reply.raw.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    });
    reply.raw.write(": connected\n\n");

    const onAccess = (e: AccessEntry) => {
      reply.raw.write(
        `event: access\ndata: ${JSON.stringify({
          ...e,
          hostLabel: hosts.label(e.hostId),
          banned: bans.checker()(e.client),
          // Offline lookup; lets the UI show where the request came from.
          country: lookupGeo(e.client).country,
        })}\n\n`,
      );
    };
    const onError = (e: ErrorEntry) => {
      reply.raw.write(
        `event: error\ndata: ${JSON.stringify({ ...e, hostLabel: hosts.label(e.hostId) })}\n\n`,
      );
    };
    watcher.on("access-entry", onAccess);
    watcher.on("error-entry", onError);

    // The auth gate only runs when the stream opens, so re-check the session
    // on each ping and close the stream once it expires or is revoked.
    const token = req.cookies?.[COOKIE];
    const ping = setInterval(() => {
      if (!validSession(token)) {
        // Destroying the socket fires the close handlers below, which clean up.
        req.raw.destroy();
        return;
      }
      reply.raw.write(": ping\n\n");
    }, 25_000);
    ping.unref();

    req.raw.on("close", () => {
      clearInterval(ping);
      watcher.off("access-entry", onAccess);
      watcher.off("error-entry", onError);
    });

    // Keep the handler open; Fastify resolves when the socket closes.
    await new Promise<void>((resolve) => req.raw.on("close", resolve));
  });
}

// Attach geo (country/city) to a top-clients row by looking up one sample.
function withGeo(db: import("../store/db.js").DB, f: A.Filter) {
  const stmt = db.prepare(
    `SELECT country, city FROM access_log WHERE client = ? LIMIT 1`,
  );
  return (row: A.Bucketed) => {
    const g = stmt.get(row.key) as unknown as
      | { country: string | null; city: string | null }
      | undefined;
    return { ...row, country: g?.country ?? null, city: g?.city ?? null };
  };
}
