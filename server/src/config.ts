import path from "node:path";

/**
 * Runtime configuration, all env-driven so the same image works in any deploy.
 * Defaults match a stock Nginx Proxy Manager container where /data is the
 * shared volume.
 */
export interface Config {
  /** Root of the NPM data volume (mounted read-only). */
  npmDataDir: string;
  /** Directory holding NPM proxy-host access/error logs. */
  logsDir: string;
  /** Path to the NPM SQLite database (read-only). */
  npmDbPath: string;
  /** Writable path for our own parsed-log database. */
  stateDbPath: string;
  /** How many days of existing logs to backfill on first boot. */
  backfillDays: number;
  /** Secret used to sign the session cookie. */
  sessionSecret: string;
  /** Session lifetime in seconds. */
  sessionTtlSeconds: number;
  /** HTTP port. */
  port: number;
  /** Host to bind. */
  host: string;
  /** Directory of the built web frontend (served as static). */
  webDir: string;
  /** Set true when served over HTTPS so the cookie gets the Secure flag. */
  secureCookie: boolean;
  /** Resend API key for threat alert emails (empty disables sending). */
  resendApiKey: string;
  /** From address for alert emails (must be a Resend-verified sender). */
  alertFrom: string;
  /** Trust X-Forwarded-* headers (true when behind NPM/a reverse proxy). */
  trustProxy: boolean;
  /** Max failed logins per IP within the window before throttling. */
  loginMaxAttempts: number;
  /** Login throttle window in minutes. */
  loginWindowMinutes: number;
}

function envInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === "") return fallback;
  const n = Number.parseInt(raw, 10);
  if (Number.isNaN(n)) throw new Error(`Env ${name} must be an integer, got "${raw}"`);
  return n;
}

function envBool(name: string, fallback: boolean): boolean {
  const raw = process.env[name];
  if (raw === undefined) return fallback;
  return ["1", "true", "yes", "on"].includes(raw.toLowerCase());
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const npmDataDir = env.NPM_DATA ?? "/data";
  const sessionSecret = env.SESSION_SECRET ?? "";
  if (sessionSecret.length < 16 && env.NODE_ENV === "production") {
    throw new Error("SESSION_SECRET must be set to at least 16 characters in production");
  }

  return {
    npmDataDir,
    logsDir: env.LOGS_DIR ?? path.join(npmDataDir, "logs"),
    npmDbPath: env.NPM_DB ?? path.join(npmDataDir, "database.sqlite"),
    stateDbPath: env.STATE_DB ?? "/state/logviewer.sqlite",
    backfillDays: envInt("BACKFILL_DAYS", 14),
    sessionSecret: sessionSecret || "dev-insecure-secret-change-me",
    sessionTtlSeconds: envInt("SESSION_TTL", 60 * 60 * 12),
    port: envInt("PORT", 8090),
    host: env.HOST ?? "0.0.0.0",
    webDir: env.WEB_DIR ?? path.resolve(process.cwd(), "../web/dist"),
    secureCookie: envBool("SECURE_COOKIE", false),
    resendApiKey: env.RESEND_API_KEY ?? "",
    alertFrom: env.ALERT_FROM ?? "ProxyLogs <onboarding@resend.dev>",
    trustProxy: envBool("TRUST_PROXY", true),
    loginMaxAttempts: envInt("LOGIN_MAX_ATTEMPTS", 10),
    loginWindowMinutes: envInt("LOGIN_WINDOW_MINUTES", 15),
  };
}
