import type { DB } from "../store/db.js";
import type { Settings } from "../store/settings.js";
import type { Mailer } from "./mailer.js";
import { DETECTORS, defaultConfig } from "./detectors.js";
import { ipMatchesAny } from "../ingest/networks.js";
import {
  SEVERITY_RANK,
  type Finding,
  type Severity,
  type ThreatConfig,
} from "./types.js";

const CONFIG_KEY = "threat_config";

export class ThreatEngine {
  #db: DB;
  #settings: Settings;
  #mailer: Mailer;
  #upsert;
  #timer: NodeJS.Timeout | null = null;
  #onLog: (msg: string, extra?: unknown) => void;

  constructor(
    db: DB,
    settings: Settings,
    mailer: Mailer,
    onLog: (msg: string, extra?: unknown) => void = () => {},
  ) {
    this.#db = db;
    this.#settings = settings;
    this.#mailer = mailer;
    this.#onLog = onLog;
    this.#upsert = db.prepare(`
      INSERT INTO threat_finding
        (rule, subject, severity, title, detail, host_label, sample, count, first_ts, last_ts, acknowledged)
      VALUES
        (@rule, @subject, @severity, @title, @detail, @hostLabel, @sample, @count, @ts, @ts, 0)
      ON CONFLICT(rule, subject) DO UPDATE SET
        severity = excluded.severity,
        detail   = excluded.detail,
        sample   = excluded.sample,
        count    = excluded.count,
        last_ts  = excluded.last_ts,
        acknowledged = 0
    `);
  }

  /** Stored config merged over defaults, so newly added detectors get defaults. */
  getConfig(): ThreatConfig {
    const base = defaultConfig();
    const saved = this.#settings.getJSON<ThreatConfig>(CONFIG_KEY);
    if (!saved) return base;
    return {
      ...base,
      ...saved,
      rules: { ...base.rules, ...saved.rules },
    };
  }

  setConfig(cfg: ThreatConfig): void {
    this.#settings.setJSON(CONFIG_KEY, cfg);
  }

  start(intervalMs = 60_000): void {
    // Run once shortly after boot, then on the interval.
    setTimeout(() => void this.evaluate(), 5_000).unref();
    this.#timer = setInterval(() => void this.evaluate(), intervalMs);
    this.#timer.unref();
  }

  stop(): void {
    if (this.#timer) clearInterval(this.#timer);
    this.#timer = null;
  }

  /** Run all enabled detectors over the rolling window and persist findings. */
  async evaluate(): Promise<void> {
    const cfg = this.getConfig();
    const to = Date.now();
    const from = to - cfg.windowMinutes * 60_000;
    const exceptions = cfg.exceptions ?? [];

    // Drop any existing findings for now-excepted subjects.
    if (exceptions.length) this.#purgeExcepted(exceptions);

    const alertable: Finding[] = [];

    for (const detector of DETECTORS) {
      const rule = cfg.rules[detector.id] ?? detector.defaults;
      if (!rule.enabled) continue;
      let raws;
      try {
        raws = detector.run(this.#db, from, to, rule);
      } catch (err) {
        this.#onLog("detector failed", { id: detector.id, err });
        continue;
      }
      for (const raw of raws) {
        // Skip trusted IPs/ranges (e.g. the operator's own address).
        if (raw.subject !== "global" && ipMatchesAny(raw.subject, exceptions)) {
          continue;
        }
        this.#upsert.run({
          rule: detector.id,
          subject: raw.subject,
          severity: rule.severity,
          title: detector.title,
          detail: raw.detail,
          hostLabel: raw.hostLabel ?? null,
          sample: raw.sample ?? null,
          count: raw.count,
          ts: to,
        });
        if (
          SEVERITY_RANK[rule.severity] >= SEVERITY_RANK[cfg.alertMinSeverity]
        ) {
          alertable.push({
            id: 0,
            rule: detector.id,
            subject: raw.subject,
            severity: rule.severity,
            title: detector.title,
            detail: raw.detail,
            hostLabel: raw.hostLabel ?? null,
            sample: raw.sample ?? null,
            count: raw.count,
            firstTs: to,
            lastTs: to,
            acknowledged: false,
          });
        }
      }
    }

    if (alertable.length) await this.#maybeAlert(cfg, alertable, to);
  }

  /** Send one bundled email for alertable findings whose rule cooldown elapsed. */
  async #maybeAlert(cfg: ThreatConfig, findings: Finding[], now: number): Promise<void> {
    if (!cfg.alertEmail || !this.#mailer.configured) return;

    const cooldownMs = cfg.cooldownMinutes * 60_000;
    const rulesReady = new Set<string>();
    const toReport: Finding[] = [];
    for (const f of findings) {
      const key = `cooldown:${f.rule}`;
      const last = Number(this.#settings.get(key) ?? 0);
      if (now - last >= cooldownMs) {
        toReport.push(f);
        rulesReady.add(f.rule);
      }
    }
    if (toReport.length === 0) return;

    const subject = `[ProxyLogs] ${toReport.length} security finding${
      toReport.length === 1 ? "" : "s"
    } (${highest(toReport)})`;
    const body = renderEmail(cfg, toReport);

    const result = await this.#mailer.send(cfg.alertEmail, subject, body);
    if (result.ok) {
      for (const rule of rulesReady) this.#settings.set(`cooldown:${rule}`, String(now));
      this.#onLog("threat alert sent", { count: toReport.length });
    } else {
      this.#onLog("threat alert failed", { error: result.error });
    }
  }

  // --- queries used by the API --------------------------------------------

  listFindings(opts: {
    minSeverity?: Severity;
    rule?: string;
    includeAcked?: boolean;
    limit?: number;
  }): Finding[] {
    const clauses: string[] = [];
    const params: Record<string, string | number> = {};
    if (opts.rule) {
      clauses.push("rule = @rule");
      params.rule = opts.rule;
    }
    if (!opts.includeAcked) clauses.push("acknowledged = 0");
    const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
    const rows = this.#db
      .prepare(
        `SELECT id, rule, subject, severity, title, detail,
                host_label AS hostLabel, sample, count,
                first_ts AS firstTs, last_ts AS lastTs, acknowledged
           FROM threat_finding ${where}
           ORDER BY last_ts DESC
           LIMIT @limit`,
      )
      .all({ ...params, limit: opts.limit ?? 500 }) as unknown as Array<
      Omit<Finding, "acknowledged"> & { acknowledged: number }
    >;
    let findings: Finding[] = rows.map((r) => ({
      ...r,
      acknowledged: r.acknowledged === 1,
    }));
    if (opts.minSeverity) {
      const min = SEVERITY_RANK[opts.minSeverity];
      findings = findings.filter((f) => SEVERITY_RANK[f.severity] >= min);
    }
    return findings;
  }

  counts(): Record<Severity, number> {
    const rows = this.#db
      .prepare(
        `SELECT severity, COUNT(*) AS n FROM threat_finding
          WHERE acknowledged = 0 GROUP BY severity`,
      )
      .all() as unknown as Array<{ severity: Severity; n: number }>;
    const out: Record<Severity, number> = {
      info: 0, low: 0, medium: 0, high: 0, critical: 0,
    };
    for (const r of rows) out[r.severity] = r.n;
    return out;
  }

  acknowledge(id: number): void {
    this.#db.prepare(`UPDATE threat_finding SET acknowledged = 1 WHERE id = ?`).run(id);
  }

  acknowledgeAll(): void {
    this.#db.prepare(`UPDATE threat_finding SET acknowledged = 1`).run();
  }

  clear(): void {
    this.#db.prepare(`DELETE FROM threat_finding`).run();
  }

  /** Remove findings whose subject matches an exception (exact IP or CIDR). */
  #purgeExcepted(exceptions: string[]): void {
    const subjects = this.#db
      .prepare(`SELECT DISTINCT subject FROM threat_finding`)
      .all() as unknown as Array<{ subject: string }>;
    const del = this.#db.prepare(`DELETE FROM threat_finding WHERE subject = ?`);
    for (const { subject } of subjects) {
      if (subject !== "global" && ipMatchesAny(subject, exceptions)) del.run(subject);
    }
  }
}

function highest(findings: Finding[]): string {
  return findings
    .map((f) => f.severity)
    .sort((a, b) => SEVERITY_RANK[b] - SEVERITY_RANK[a])[0] as string;
}

function renderEmail(cfg: ThreatConfig, findings: Finding[]): string {
  const lines = [
    "ProxyLogs detected suspicious activity against your Nginx Proxy Manager hosts.",
    `Window: last ${cfg.windowMinutes} minutes.`,
    "",
  ];
  for (const f of findings) {
    lines.push(`• [${f.severity.toUpperCase()}] ${f.title}`);
    lines.push(`    subject: ${f.subject}`);
    lines.push(`    ${f.detail}`);
    if (f.sample) lines.push(`    sample: ${f.sample}`);
    lines.push("");
  }
  lines.push("Open the Threats tab in ProxyLogs for the full picture.");
  return lines.join("\n");
}
