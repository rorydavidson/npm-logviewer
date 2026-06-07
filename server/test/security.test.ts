import { describe, it, expect } from "vitest";
import { RateLimiter } from "../src/security/rateLimit.js";
import { sanitizeThreatConfig } from "../src/threats/validate.js";

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
