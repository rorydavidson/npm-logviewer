import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { Config } from "../config.js";
import type { Store } from "../store/store.js";
import type { NpmDb } from "../npm/npmDb.js";
import type { HostMap } from "../npm/hostMap.js";
import type { Watcher } from "../ingest/watcher.js";
import { verifyCredentials } from "../auth/auth.js";
import { createToken, verifyToken, type SessionPayload } from "../auth/session.js";
import { parseFilter } from "./filter.js";
import * as A from "../store/analytics.js";
import type { AccessEntry, ErrorEntry } from "../types.js";
import type { ThreatEngine } from "../threats/engine.js";
import type { Mailer } from "../threats/mailer.js";
import { DETECTORS } from "../threats/detectors.js";
import { sanitizeThreatConfig } from "../threats/validate.js";
import type { Severity } from "../threats/types.js";
import { RateLimiter } from "../security/rateLimit.js";

const COOKIE = "lv_session";

export interface AppCtx {
  config: Config;
  store: Store;
  npm: NpmDb;
  hosts: HostMap;
  watcher: Watcher;
  engine: ThreatEngine;
  mailer: Mailer;
}

function num(v: unknown, fallback: number): number {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

export async function registerRoutes(app: FastifyInstance, ctx: AppCtx): Promise<void> {
  const { config, store, npm, hosts, watcher, engine, mailer } = ctx;
  const db = store.db;

  const loginLimiter = new RateLimiter(
    config.loginMaxAttempts,
    config.loginWindowMinutes * 60_000,
  );

  // --- auth gate for everything under /api except login -------------------
  app.addHook("preHandler", async (req: FastifyRequest, reply: FastifyReply) => {
    if (!req.url.startsWith("/api/")) return;
    if (req.url.startsWith("/api/login")) return;
    const token = req.cookies?.[COOKIE];
    const session = verifyToken(token, config.sessionSecret);
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

    const { email, password } = (req.body ?? {}) as {
      email?: string;
      password?: string;
    };
    if (!email || !password) {
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
      { email: result.email!, name: result.name ?? result.email!, exp },
      config.sessionSecret,
    );
    reply.setCookie(COOKIE, token, {
      httpOnly: true,
      sameSite: "lax",
      secure: config.secureCookie,
      path: "/",
      maxAge: config.sessionTtlSeconds,
    });
    return { ok: true, name: result.name, email: result.email };
  });

  app.post("/api/logout", async (_req, reply) => {
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
    const limit = Math.min(500, num(q.limit, 100));
    const offset = Math.max(0, num(q.offset, 0));
    const page = A.queryAccess(db, f, limit, offset);
    return {
      total: page.total,
      limit,
      offset,
      rows: page.rows.map((r) => ({ ...r, hostLabel: hosts.label(r.hostId) })),
    };
  });

  app.get("/api/errors", async (req) => {
    const q = req.query as Record<string, string>;
    const f = parseFilter(q);
    const limit = Math.min(500, num(q.limit, 100));
    const offset = Math.max(0, num(q.offset, 0));
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
    return {
      counts: engine.counts(),
      findings: findings.map((f) => ({
        ...f,
        // For IP subjects, attach geo so the UI can show a flag.
        ...geoForSubject(db, f.subject),
        // Which proxy hosts this subject has been hitting.
        targets: targetsForSubject(db, hosts, f.subject, f.lastTs),
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
        `event: access\ndata: ${JSON.stringify({ ...e, hostLabel: hosts.label(e.hostId) })}\n\n`,
      );
    };
    const onError = (e: ErrorEntry) => {
      reply.raw.write(
        `event: error\ndata: ${JSON.stringify({ ...e, hostLabel: hosts.label(e.hostId) })}\n\n`,
      );
    };
    watcher.on("access-entry", onAccess);
    watcher.on("error-entry", onError);

    const ping = setInterval(() => reply.raw.write(": ping\n\n"), 25_000);
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

// Look up geo for a finding subject if it looks like a client IP.
function geoForSubject(
  db: import("../store/db.js").DB,
  subject: string,
): { country: string | null; city: string | null } {
  const g = db
    .prepare(`SELECT country, city FROM access_log WHERE client = ? LIMIT 1`)
    .get(subject) as unknown as
    | { country: string | null; city: string | null }
    | undefined;
  return { country: g?.country ?? null, city: g?.city ?? null };
}

// The proxy hosts a finding subject (client IP) has been hitting, most first.
function targetsForSubject(
  db: import("../store/db.js").DB,
  hosts: HostMap,
  subject: string,
  lastTs: number,
): Array<{ hostId: number | null; label: string; count: number }> {
  if (subject === "global") return [];
  // Look back a day from when the finding was last seen.
  const from = lastTs - 24 * 60 * 60 * 1000;
  const rows = db
    .prepare(
      `SELECT host_id AS hostId, COUNT(*) AS count
         FROM access_log
        WHERE client = ? AND ts >= ? AND ts <= ?
        GROUP BY host_id
        ORDER BY count DESC
        LIMIT 5`,
    )
    .all(subject, from, lastTs) as unknown as Array<{
    hostId: number | null;
    count: number;
  }>;
  return rows.map((r) => ({
    hostId: r.hostId,
    label: hosts.label(r.hostId),
    count: r.count,
  }));
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
