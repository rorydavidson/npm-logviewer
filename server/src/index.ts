import fs from "node:fs";
import Fastify from "fastify";
import cookie from "@fastify/cookie";
import fastifyStatic from "@fastify/static";
import { loadConfig } from "./config.js";
import { Store } from "./store/store.js";
import { NpmDb } from "./npm/npmDb.js";
import { HostMap } from "./npm/hostMap.js";
import { Watcher } from "./ingest/watcher.js";
import { registerRoutes, type AppCtx } from "./api/routes.js";

async function main(): Promise<void> {
  const config = loadConfig();
  const app = Fastify({ logger: { level: process.env.LOG_LEVEL ?? "info" } });

  await app.register(cookie);

  const store = new Store(config.stateDbPath);
  const npm = new NpmDb(config.npmDbPath);
  const hosts = new HostMap(npm);
  hosts.startAutoRefresh();

  const watcher = new Watcher(store, config.logsDir, config.backfillDays);

  const ctx: AppCtx = { config, store, npm, hosts, watcher };
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
    { logsDir: config.logsDir, npmDb: config.npmDbPath },
    "nginx-logviewer ready",
  );
}

main().catch((err) => {
  console.error("fatal startup error", err);
  process.exit(1);
});
