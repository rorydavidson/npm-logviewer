import type { DB } from "../store/db.js";
import type { Settings } from "../store/settings.js";
import type { Mailer } from "./mailer.js";
import { DETECTORS, defaultConfig } from "./detectors.js";
import { classifyIp, ipMatchesAny } from "../ingest/networks.js";
import { geoForSubject, targetsForSubject, type TargetHost } from "./enrich.js";
import type { BanService } from "../bans/service.js";
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
  #siteUrl: string;
  #label: (hostId: number | null) => string;
  #bans: BanService | null;

  constructor(
    db: DB,
    settings: Settings,
    mailer: Mailer,
    onLog: (msg: string, extra?: unknown) => void = () => {},
    siteUrl = "",
    label: (hostId: number | null) => string = (id) =>
      id === null ? "fallback" : `host-${id}`,
    bans: BanService | null = null,
  ) {
    this.#db = db;
    this.#settings = settings;
    this.#mailer = mailer;
    this.#onLog = onLog;
    this.#siteUrl = siteUrl.replace(/\/+$/, "");
    this.#label = label;
    this.#bans = bans;
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

  setBanService(bans: BanService): void {
    this.#bans = bans;
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
    // Track every raised finding by subject for the auto-ban decision.
    const bySubject = new Map<string, { severities: Severity[]; rules: Set<string> }>();

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
        // Never act on Cloudflare edge IPs. If NPM logs the CDN edge instead of
        // the real visitor (missing CF-Connecting-IP real-IP config), the edge
        // address is not the attacker — banning it blocks the CDN for everyone.
        if (raw.subject !== "global" && classifyIp(raw.subject) === "cloudflare") {
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
        if (raw.subject !== "global") {
          let agg = bySubject.get(raw.subject);
          if (!agg) {
            agg = { severities: [], rules: new Set() };
            bySubject.set(raw.subject, agg);
          }
          agg.severities.push(rule.severity);
          agg.rules.add(detector.id);
        }
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

    if (cfg.autoBan?.enabled && this.#bans) await this.#maybeAutoBan(cfg, bySubject, to);
    if (alertable.length) await this.#maybeAlert(cfg, alertable, to);
  }

  /** Auto-ban subjects that meet the configured severity + finding-count bar. */
  async #maybeAutoBan(
    cfg: ThreatConfig,
    bySubject: Map<string, { severities: Severity[]; rules: Set<string> }>,
    now: number,
  ): Promise<void> {
    const bans = this.#bans;
    if (!bans) return;
    const minRank = SEVERITY_RANK[cfg.autoBan.minSeverity];
    let bannedAny = false;
    for (const [ip, agg] of bySubject) {
      const peak = Math.max(...agg.severities.map((s) => SEVERITY_RANK[s]));
      if (peak < minRank) continue;
      if (agg.rules.size < cfg.autoBan.minFindings) continue;
      if (bans.has(ip)) continue;
      const result = await bans.ban(ip, {
        reason: `auto: ${agg.rules.size} findings (peak ${cfg.autoBan.minSeverity}+)`,
        rule: [...agg.rules].join(","),
        auto: true,
        now,
        deferSync: true, // batch: write the file + reload nginx once below
      });
      if (result.ok) bannedAny = true;
      else this.#onLog("auto-ban skipped", { ip, reason: result.reason });
    }
    // One file write + at most one nginx reload per cycle, however many bans.
    if (bannedAny) await bans.sync();
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
    // Require enough findings before alerting — lets the user demand a
    // concerted attack (multiple findings) rather than a single hit.
    if (toReport.length < cfg.alertMinFindings) return;

    // Enrich each finding with geo + targeted hosts for the email.
    const enriched: EnrichedFinding[] = toReport.map((f) => ({
      ...f,
      geo: geoForSubject(this.#db, f.subject),
      targets: targetsForSubject(this.#db, this.#label, f.subject, f.lastTs),
    }));

    const subject = `[ProxyLogs] ${toReport.length} security finding${
      toReport.length === 1 ? "" : "s"
    } (${highest(toReport)})`;
    const text = renderText(cfg, enriched, this.#siteUrl);
    const html = renderHtml(cfg, enriched, this.#siteUrl);

    const result = await this.#mailer.send(cfg.alertEmail, subject, text, html);
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

interface EnrichedFinding extends Finding {
  geo: { country: string | null; city: string | null };
  targets: TargetHost[];
}

function highest(findings: Finding[]): string {
  return findings
    .map((f) => f.severity)
    .sort((a, b) => SEVERITY_RANK[b] - SEVERITY_RANK[a])[0] as string;
}

const PAD_MS = 10 * 60 * 1000;

function logsLink(siteUrl: string, f: Finding): string | null {
  if (!siteUrl || f.subject === "global") return null;
  const q = new URLSearchParams({
    client: f.subject,
    from: String(f.firstTs - PAD_MS),
    to: String(f.lastTs + PAD_MS),
  });
  return `${siteUrl}/logs?${q.toString()}`;
}

function location(geo: { country: string | null; city: string | null }): string {
  return [geo.city, geo.country].filter(Boolean).join(", ");
}

function fmtTs(ts: number): string {
  return new Date(ts).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

function renderText(cfg: ThreatConfig, findings: EnrichedFinding[], siteUrl: string): string {
  const lines = [
    "ProxyLogs detected suspicious activity against your Nginx Proxy Manager hosts.",
    `Window: last ${cfg.windowMinutes} minutes · ${findings.length} finding(s).`,
    "",
  ];
  for (const f of findings) {
    lines.push(`• [${f.severity.toUpperCase()}] ${f.title}`);
    lines.push(`    source: ${f.subject}${location(f.geo) ? ` (${location(f.geo)})` : ""}`);
    if (f.targets.length) {
      lines.push(
        `    targets: ${f.targets.map((t) => `${t.label} (${t.count})`).join(", ")}`,
      );
    }
    lines.push(`    hits: ${f.count}`);
    lines.push(`    ${f.detail}`);
    lines.push(`    first seen: ${fmtTs(f.firstTs)}  ·  last seen: ${fmtTs(f.lastTs)}`);
    if (f.sample) lines.push(`    sample: ${f.sample}`);
    const link = logsLink(siteUrl, f);
    if (link) lines.push(`    investigate: ${link}`);
    lines.push("");
  }
  lines.push(
    siteUrl
      ? `Open the Threats tab: ${siteUrl}/threats`
      : "Open the Threats tab in ProxyLogs for the full picture. (Set SITE_URL to get direct links here.)",
  );
  return lines.join("\n");
}

const SEV_COLOUR: Record<string, string> = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#d97706",
  low: "#2563eb",
  info: "#6b7280",
};

function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function renderHtml(cfg: ThreatConfig, findings: EnrichedFinding[], siteUrl: string): string {
  const cards = findings
    .map((f) => {
      const colour = SEV_COLOUR[f.severity] ?? SEV_COLOUR.info;
      const loc = location(f.geo);
      const link = logsLink(siteUrl, f);
      const targets = f.targets.length
        ? f.targets
            .map(
              (t) =>
                `<span style="display:inline-block;background:#eef2f7;color:#111827;border:1px solid #cbd5e1;border-radius:4px;padding:2px 6px;margin:0 4px 4px 0;font-size:12px;">${esc(
                  t.label,
                )} <strong>${t.count}</strong></span>`,
            )
            .join("")
        : '<span style="color:#9ca3af;font-size:12px;">all hosts</span>';

      return `
      <tr><td style="padding:14px 16px;border:1px solid #e5e7eb;border-radius:8px;">
        <div style="margin-bottom:6px;">
          <span style="display:inline-block;background:${colour};color:#fff;border-radius:4px;padding:2px 8px;font-size:11px;font-weight:700;text-transform:uppercase;">${esc(
            f.severity,
          )}</span>
          <span style="font-weight:600;font-size:15px;margin-left:8px;">${esc(f.title)}</span>
        </div>
        <table style="font-size:13px;color:#374151;border-collapse:collapse;">
          <tr><td style="padding:2px 10px 2px 0;color:#6b7280;">Source</td><td><strong>${esc(
            f.subject,
          )}</strong>${loc ? ` <span style="color:#6b7280;">(${esc(loc)})</span>` : ""}</td></tr>
          <tr><td style="padding:2px 10px 2px 0;color:#6b7280;">Targets</td><td>${targets}</td></tr>
          <tr><td style="padding:2px 10px 2px 0;color:#6b7280;">Hits</td><td>${f.count}</td></tr>
          <tr><td style="padding:2px 10px 2px 0;color:#6b7280;">Detail</td><td>${esc(
            f.detail,
          )}</td></tr>
          <tr><td style="padding:2px 10px 2px 0;color:#6b7280;">Seen</td><td>${esc(
            fmtTs(f.firstTs),
          )} → ${esc(fmtTs(f.lastTs))}</td></tr>
          ${
            f.sample
              ? `<tr><td style="padding:2px 10px 2px 0;color:#6b7280;">Sample</td><td style="font-family:monospace;font-size:12px;word-break:break-all;">${esc(
                  f.sample,
                )}</td></tr>`
              : ""
          }
        </table>
        ${
          link
            ? `<div style="margin-top:8px;"><a href="${esc(
                link,
              )}" style="color:#2563eb;font-size:13px;text-decoration:none;">View matching log entries →</a></div>`
            : ""
        }
      </td></tr>
      <tr><td style="height:10px;"></td></tr>`;
    })
    .join("");

  const threatsLink = siteUrl
    ? `<a href="${esc(siteUrl)}/threats" style="display:inline-block;background:#2563eb;color:#fff;text-decoration:none;padding:9px 16px;border-radius:6px;font-size:14px;">Open the Threats dashboard</a>`
    : `<span style="color:#6b7280;font-size:13px;">Set SITE_URL to get direct links in these emails.</span>`;

  return `<!doctype html><html><body style="margin:0;background:#f3f4f6;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#111827;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f3f4f6;padding:24px 0;">
    <tr><td align="center">
      <table role="presentation" width="640" cellpadding="0" cellspacing="0" style="max-width:640px;width:100%;background:#ffffff;border-radius:10px;padding:24px;">
        <tr><td>
          <h1 style="margin:0 0 4px;font-size:18px;">🛡️ ProxyLogs security alert</h1>
          <p style="margin:0 0 16px;color:#6b7280;font-size:13px;">
            ${findings.length} finding${findings.length === 1 ? "" : "s"} in the last ${
              cfg.windowMinutes
            } minutes against your Nginx Proxy Manager hosts.
          </p>
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0">${cards}</table>
          <div style="margin-top:8px;">${threatsLink}</div>
          <p style="margin:20px 0 0;color:#9ca3af;font-size:11px;">
            You are receiving this because ProxyLogs threat alerts are enabled.
            Adjust rules, severities, and the alert threshold in the Threats tab.
          </p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>`;
}
