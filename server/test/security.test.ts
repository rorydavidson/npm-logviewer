import { describe, it, expect } from "vitest";
import Fastify from "fastify";
import { RateLimiter } from "../src/security/rateLimit.js";
import { sanitizeThreatConfig } from "../src/threats/validate.js";
import {
  checkSessionSecret,
  loadConfig,
  parseTrustProxy,
  DEFAULT_TRUSTED_PROXIES,
} from "../src/config.js";

describe("session secret guard", () => {
  it("rejects a missing or short secret", () => {
    expect(checkSessionSecret("")).toMatch(/at least 16/);
    expect(checkSessionSecret("tooshort")).toMatch(/at least 16/);
  });

  it("rejects the placeholders published in the example files", () => {
    // Long enough to pass a length check, but public — so forgeable.
    expect(checkSessionSecret("change-me-to-a-long-random-string")).toMatch(
      /placeholder/,
    );
    expect(checkSessionSecret("dev-insecure-secret-change-me")).toMatch(/placeholder/);
    expect(checkSessionSecret("your-secret-here-goes-now")).toMatch(/placeholder/);
  });

  it("accepts a generated secret", () => {
    expect(checkSessionSecret("9f2c1ab4e77d05c3a1b8e6f409d2ccf7")).toBeNull();
  });

  it("refuses to start in production on a placeholder", () => {
    const env = {
      NODE_ENV: "production",
      SESSION_SECRET: "change-me-to-a-long-random-string",
    } as NodeJS.ProcessEnv;
    expect(() => loadConfig(env)).toThrow(/placeholder/);
  });

  it("leaves development alone", () => {
    const env = { SESSION_SECRET: "" } as NodeJS.ProcessEnv;
    expect(() => loadConfig(env)).not.toThrow();
  });
});

describe("RateLimiter", () => {
  it("limits after max attempts within the window", () => {
    const rl = new RateLimiter(3, 1000);
    const t0 = 1_000_000;
    expect(rl.isLimited("ip", t0)).toBe(false);
    rl.record("ip", t0);
    rl.record("ip", t0);
    rl.record("ip", t0);
    expect(rl.isLimited("ip", t0)).toBe(true);
  });

  it("resets after the window elapses", () => {
    const rl = new RateLimiter(2, 1000);
    const t0 = 1_000_000;
    rl.record("ip", t0);
    rl.record("ip", t0);
    expect(rl.isLimited("ip", t0)).toBe(true);
    expect(rl.isLimited("ip", t0 + 1001)).toBe(false);
  });

  it("reset() clears a key", () => {
    const rl = new RateLimiter(1, 1000);
    const t0 = 1_000_000;
    rl.record("ip", t0);
    expect(rl.isLimited("ip", t0)).toBe(true);
    rl.reset("ip");
    expect(rl.isLimited("ip", t0)).toBe(false);
  });

  it("tracks keys independently", () => {
    const rl = new RateLimiter(1, 1000);
    const t0 = 1_000_000;
    rl.record("a", t0);
    expect(rl.isLimited("a", t0)).toBe(true);
    expect(rl.isLimited("b", t0)).toBe(false);
  });
});

describe("sanitizeThreatConfig", () => {
  it("clamps numbers and whitelists severities", () => {
    const c = sanitizeThreatConfig({
      windowMinutes: 999999,
      cooldownMinutes: -5,
      alertMinSeverity: "nonsense",
    });
    expect(c.windowMinutes).toBe(1440);
    expect(c.cooldownMinutes).toBe(0);
    expect(c.alertMinSeverity).toBe("critical"); // default
  });

  it("drops unknown rule ids and keeps known ones", () => {
    const c = sanitizeThreatConfig({
      rules: { evilRule: { enabled: true, severity: "critical" } },
    });
    expect((c.rules as Record<string, unknown>).evilRule).toBeUndefined();
    expect(c.rules.scanner404).toBeDefined();
  });

  it("coerces and caps string lists", () => {
    const big = Array.from({ length: 5000 }, (_, i) => `1.2.3.${i}`);
    const c = sanitizeThreatConfig({ exceptions: [...big, 123, null, "  10.0.0.1  "] });
    expect(c.exceptions.length).toBeLessThanOrEqual(1000);
    expect(c.exceptions.every((e) => typeof e === "string")).toBe(true);
  });

  it("rejects a non-string alert email type", () => {
    const c = sanitizeThreatConfig({ alertEmail: { evil: true } });
    expect(c.alertEmail).toBe("");
  });

  it("ignores rule threshold for non-threshold rules but keeps severity", () => {
    const c = sanitizeThreatConfig({
      rules: { scanner404: { enabled: false, severity: "low", threshold: 5 } },
    });
    expect(c.rules.scanner404?.enabled).toBe(false);
    expect(c.rules.scanner404?.severity).toBe("low");
    expect(c.rules.scanner404?.threshold).toBe(5);
  });
});

describe("trusted proxies", () => {
  it("maps unset and the old boolean true to private ranges only", () => {
    expect(parseTrustProxy(undefined)).toBe(DEFAULT_TRUSTED_PROXIES);
    expect(parseTrustProxy("true")).toBe(DEFAULT_TRUSTED_PROXIES);
    expect(parseTrustProxy("false")).toBe(false);
    expect(parseTrustProxy("172.18.0.0/16")).toBe("172.18.0.0/16");
  });

  async function clientIp(remoteAddress: string, xff: string): Promise<string> {
    const app = Fastify({ trustProxy: parseTrustProxy(undefined) });
    app.get("/ip", async (req) => req.ip);
    const res = await app.inject({
      url: "/ip",
      remoteAddress,
      headers: { "x-forwarded-for": xff },
    });
    await app.close();
    return res.body;
  }

  it("ignores a spoofed X-Forwarded-For entry behind NPM", async () => {
    // Client sent "6.6.6.6"; NPM (on a Docker network) appended the real IP.
    expect(await clientIp("172.18.0.2", "6.6.6.6, 1.2.3.4")).toBe("1.2.3.4");
  });

  it("ignores X-Forwarded-For from a public peer", async () => {
    expect(await clientIp("1.2.3.4", "6.6.6.6")).toBe("1.2.3.4");
  });
});
