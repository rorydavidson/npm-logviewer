export type Severity = "info" | "low" | "medium" | "high" | "critical";

export const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

/** Per-rule, user-editable configuration. */
export interface RuleConfig {
  enabled: boolean;
  severity: Severity;
  /** Count over the window at which the rule fires (where applicable). */
  threshold?: number;
  /** SQL LIKE patterns (where applicable), one entry per pattern. */
  patterns?: string[];
}

/** Whole threat-detection configuration, persisted in app_settings. */
export interface ThreatConfig {
  windowMinutes: number;
  alertEmail: string;
  alertMinSeverity: Severity;
  cooldownMinutes: number;
  rules: Record<string, RuleConfig>;
}

/** What a detector emits before severity/title are attached. */
export interface RawFinding {
  /** IP, host, or "global" — the unique target of the finding. */
  subject: string;
  count: number;
  detail: string;
  sample?: string;
  hostLabel?: string;
}

/** A persisted finding. */
export interface Finding {
  id: number;
  rule: string;
  subject: string;
  severity: Severity;
  title: string;
  detail: string;
  hostLabel: string | null;
  sample: string | null;
  count: number;
  firstTs: number;
  lastTs: number;
  acknowledged: boolean;
}
