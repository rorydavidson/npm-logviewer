import { DETECTOR_BY_ID, defaultConfig } from "./detectors.js";
import { SEVERITY_RANK, type RuleConfig, type Severity, type ThreatConfig } from "./types.js";

const SEVERITIES = Object.keys(SEVERITY_RANK) as Severity[];

function clampInt(v: unknown, min: number, max: number, fallback: number): number {
  const n = Math.trunc(Number(v));
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, n));
}

function asSeverity(v: unknown, fallback: Severity): Severity {
  return SEVERITIES.includes(v as Severity) ? (v as Severity) : fallback;
}

function asStringList(v: unknown, maxItems: number, maxLen: number): string[] {
  if (!Array.isArray(v)) return [];
  const out: string[] = [];
  for (const item of v) {
    if (typeof item !== "string") continue;
    const s = item.trim().slice(0, maxLen);
    if (s) out.push(s);
    if (out.length >= maxItems) break;
  }
  return out;
}

/**
 * Coerce an untrusted config object into a safe, well-formed ThreatConfig.
 *
 * The threat endpoints are authenticated, but this still defends against
 * malformed input and unbounded values: numbers are clamped, severities and
 * rule ids are whitelisted, and string lists are length-capped. Unknown rule
 * ids are dropped. Anything missing falls back to the defaults.
 */
export function sanitizeThreatConfig(input: unknown): ThreatConfig {
  const base = defaultConfig();
  const raw = (input ?? {}) as Partial<ThreatConfig>;

  const rules: Record<string, RuleConfig> = {};
  const rawRules = (raw.rules ?? {}) as Record<string, Partial<RuleConfig>>;
  for (const [id, def] of DETECTOR_BY_ID) {
    const r = rawRules[id] ?? {};
    rules[id] = {
      enabled: typeof r.enabled === "boolean" ? r.enabled : def.defaults.enabled,
      severity: asSeverity(r.severity, def.defaults.severity),
      threshold:
        def.editable.threshold
          ? clampInt(r.threshold, 1, 1_000_000_000, def.defaults.threshold ?? 1)
          : def.defaults.threshold,
      patterns: def.editable.patterns
        ? asStringList(r.patterns ?? def.defaults.patterns, 500, 200)
        : def.defaults.patterns,
    };
  }

  return {
    windowMinutes: clampInt(raw.windowMinutes, 1, 1440, base.windowMinutes),
    cooldownMinutes: clampInt(raw.cooldownMinutes, 0, 10080, base.cooldownMinutes),
    alertMinSeverity: asSeverity(raw.alertMinSeverity, base.alertMinSeverity),
    alertEmail:
      typeof raw.alertEmail === "string" ? raw.alertEmail.trim().slice(0, 320) : "",
    exceptions: asStringList(raw.exceptions, 1000, 64),
    rules,
  };
}
