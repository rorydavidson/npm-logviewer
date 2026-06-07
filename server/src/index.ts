import fs from "node:fs";
import Fastify from "fastify";
import cookie from "@fastify/cookie";
import fastifyStatic from "@fastify/static";
import { loadConfig } from "./config.js";
import { Store } from "./store/store.js";
import { NpmDb } from "./npm/npmDb.js";
import { HostMap } from "./npm/hostMap.js";
import { Watcher } from "./ingest/watcher.js";
import { Settings } from "./store/settings.js";
import { Mailer } from "./threats/mailer.js";
import { ThreatEngine } from "./threats/engine.js";
import { registerRoutes, type AppCtx } from "./api/routes.js";
import { registerSecurityHeaders } from "./security/headers.js";

async function main(): Promise<void> {
  const config = loadConfig();
  const app = Fastify({
    logger: { level: process.env.LOG_LEVEL ?? "info" },
    // Behind NPM the real client IP comes via X-Forwarded-For; trusting it lets
    // the login rate limiter key on the actual client rather than the proxy.
    trustProxy: config.trustProxy,
  });

  registerSecurityHeaders(app, { hsts: config.secureCookie });
  await app.register(cookie);

  const store = new Store(config.stateDbPath);
  const npm = new NpmDb(config.npmDbPath);
  const hosts = new HostMap(npm);
  hosts.startAutoRefresh();

  const watcher = new Watcher(store, config.logsDir, config.backfillDays);

  const settings = new Settings(store.db);
  const mailer = new Mailer({ apiKey: config.resendApiKey, from: config.alertFrom });
  const engine = new ThreatEngine(
    store.db,
    settings,
    mailer,
    (msg, extra) => app.log.info({ ...(extra as object) }, msg),
    config.siteUrl,
    (id) => hosts.label(id),
  );

  const ctx: AppCtx = { config, store, npm, hosts, watcher, engine, mailer };
  await registerRoutes(app, ctx);

  // Serve the built frontend if present (single-container deployment).
  if (fs.existsSync(config.webDir)) {
    await app.register(fastifyStatic, { root: config.webDir, wildcard: false });
    // SPA fallback: anything not matched and not an API call returns index.html.
    app.setNotFoundHandler((req, reply) => {
      if (req.url.startsWith("/api/")) {
        return reply.code(404).send({ error: "not found" });
      }
      return reply.sendFile("index.html");
    });
  }

  // Kick off ingestion (backfill + watch) without blocking server start.
  watcher.start().catch((err) => app.log.error({ err }, "watcher failed to start"));
  watcher.on("ingest-error", ({ file, err }) =>
    app.log.warn({ file, err }, "ingest error"),
  );

  // Background threat detection: evaluates a rolling window every minute and
  // emails alerts (via Resend) when findings reach the configured severity.
  engine.start();

  // Daily retention prune to the configured backfill window.
  if (config.backfillDays > 0) {
    const prune = setInterval(() => {
      const removed = store.pruneBefore(Date.now() - config.backfillDays * 86_400_000);
      if (removed) app.log.info({ removed }, "pruned old rows");
    }, 86_400_000);
    prune.unref();
  }

  const shutdown = async (signal: string) => {
    app.log.info({ signal }, "shutting down");
    hosts.stop();
    engine.stop();
    await watcher.stop();
    await app.close();
    store.close();
    npm.close();
    process.exit(0);
  };
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
  process.on("SIGINT", () => void shutdown("SIGINT"));

  await app.listen({ port: config.port, host: config.host });
  app.log.info(
    {
      logsDir: config.logsDir,
      npmDb: config.npmDbPath,
      siteUrl: config.siteUrl || "(unset)",
      emailAlerts: config.resendApiKey ? "enabled" : "disabled",
    },
    "nginx-logviewer ready",
  );
  if (config.resendApiKey && !config.siteUrl) {
    app.log.warn(
      "SITE_URL is not set, so alert emails will not include dashboard links. " +
        "Add SITE_URL to the container environment (not just .env).",
    );
  }
}

main().catch((err) => {
  console.error("fatal startup error", err);
  process.exit(1);
});
