import type { DB } from "../store/db.js";
import type { RawFinding, RuleConfig } from "./types.js";

export interface Detector {
  id: string;
  title: string;
  description: string;
  defaults: RuleConfig;
  /** Which fields the UI should let the user edit. */
  editable: { threshold: boolean; patterns: boolean };
  run(db: DB, from: number, to: number, cfg: RuleConfig): RawFinding[];
}

const SUBJECT_CAP = 50;

/** Build `col LIKE @p0 OR col LIKE @p1 ...` plus the bound params. */
function likeAny(
  col: string,
  patterns: string[],
): { sql: string; params: Record<string, string> } {
  const params: Record<string, string> = {};
  const parts = patterns.map((p, i) => {
    params[`p${i}`] = p;
    return `${col} LIKE @p${i}`;
  });
  return { sql: parts.length ? `(${parts.join(" OR ")})` : "0", params };
}

type Row = { subject: string; count: number; sample: string | null };

/** Group offending requests by client IP, with a sample URI and total count. */
function byClient(
  db: DB,
  from: number,
  to: number,
  extraSql: string,
  extraParams: Record<string, string | number>,
  threshold: number,
): RawFinding[] {
  const rows = db
    .prepare(
      `SELECT client AS subject, COUNT(*) AS count, MAX(uri) AS sample
         FROM access_log
        WHERE ts >= @from AND ts < @to AND client != '' AND ${extraSql}
        GROUP BY client
       HAVING count >= @threshold
        ORDER BY count DESC
        LIMIT ${SUBJECT_CAP}`,
    )
    .all({ from, to, threshold, ...extraParams }) as unknown as Row[];
  return rows.map((r) => ({
    subject: r.subject,
    count: r.count,
    sample: r.sample ?? undefined,
    detail: `${r.count} matching requests in the window`,
  }));
}

export const DETECTORS: Detector[] = [
  {
    id: "scanner404",
    title: "404 scanning",
    description:
      "A single client generating a large number of 404s, typical of a scanner walking for files that do not exist.",
    defaults: { enabled: true, severity: "high", threshold: 30 },
    editable: { threshold: true, patterns: false },
    run: (db, from, to, cfg) =>
      byClient(db, from, to, "status = 404", {}, cfg.threshold ?? 30),
  },
  {
    id: "authAbuse",
    title: "Auth brute force",
    description:
      "Repeated 401/403 responses to one client, suggesting credential stuffing or forbidden-area probing.",
    defaults: { enabled: true, severity: "critical", threshold: 15 },
    editable: { threshold: true, patterns: false },
    run: (db, from, to, cfg) =>
      byClient(
        db,
        from,
        to,
        "status IN (401, 403)",
        {},
        cfg.threshold ?? 15,
      ),
  },
  {
    id: "badPaths",
    title: "Known exploit paths",
    description:
      "Requests for sensitive or well-known vulnerable paths (.env, .git, wp-login, phpMyAdmin, etc.).",
    defaults: {
      enabled: true,
      severity: "critical",
      threshold: 1,
      patterns: [
        "%/.env%",
        "%/.git%",
        "%/wp-login%",
        "%/wp-admin%",
        "%/xmlrpc.php%",
        "%/phpmyadmin%",
        "%/.aws%",
        "%/.ssh%",
        "%/actuator%",
        "%/vendor/phpunit%",
        "%/cgi-bin%",
        "%/boaform%",
        "%/solr/%",
        "%/config.json%",
        "%/.well-known/security%",
      ],
    },
    editable: { threshold: true, patterns: true },
    run: (db, from, to, cfg) => {
      const like = likeAny("uri", cfg.patterns ?? []);
      return byClient(db, from, to, like.sql, like.params, cfg.threshold ?? 1);
    },
  },
  {
    id: "injection",
    title: "SQLi / XSS / traversal payloads",
    description:
      "URIs containing injection or path-traversal signatures (UNION SELECT, <script>, ../, /etc/passwd, etc.).",
    defaults: {
      enabled: true,
      severity: "critical",
      threshold: 1,
      patterns: [
        "%union%select%",
        "%or%1=1%",
        "%' or '%",
        "%<script%",
        "%onerror=%",
        "%/etc/passwd%",
        "%information_schema%",
        "%sleep(%",
        "%benchmark(%",
        "%../%",
        "%..%2f%",
        "%base64_decode%",
        "%cmd=%",
        "%exec(%",
      ],
    },
    editable: { threshold: true, patterns: true },
    run: (db, from, to, cfg) => {
      const like = likeAny("uri", cfg.patterns ?? []);
      return byClient(db, from, to, like.sql, like.params, cfg.threshold ?? 1);
    },
  },
  {
    id: "badAgents",
    title: "Hacking-tool user agents",
    description:
      "Requests whose user agent matches known scanning/attack tools (sqlmap, nikto, nmap, masscan, etc.) or is empty.",
    defaults: {
      enabled: true,
      severity: "high",
      threshold: 1,
      patterns: [
        "%sqlmap%",
        "%nikto%",
        "%nmap%",
        "%masscan%",
        "%nessus%",
        "%dirbuster%",
        "%gobuster%",
        "%hydra%",
        "%wpscan%",
        "%zgrab%",
        "%acunetix%",
        "%curl/%",
        "%python-requests%",
      ],
    },
    editable: { threshold: true, patterns: true },
    run: (db, from, to, cfg) => {
      const like = likeAny("user_agent", cfg.patterns ?? []);
      const sql = `(${like.sql} OR user_agent = '-' OR user_agent = '')`;
      return byClient(db, from, to, sql, like.params, cfg.threshold ?? 1);
    },
  },
  {
    id: "flood",
    title: "Request flood",
    description:
      "A single client making an unusually high number of requests in the window (possible DoS or aggressive crawling).",
    defaults: { enabled: true, severity: "high", threshold: 300 },
    editable: { threshold: true, patterns: false },
    run: (db, from, to, cfg) =>
      byClient(db, from, to, "1 = 1", {}, cfg.threshold ?? 300),
  },
  {
    id: "hostScan",
    title: "Cross-host scanning",
    description:
      "One client hitting many different proxy hosts, a sign of someone enumerating everything you run.",
    defaults: { enabled: true, severity: "high", threshold: 5 },
    editable: { threshold: true, patterns: false },
    run: (db, from, to, cfg) => {
      const rows = db
        .prepare(
          `SELECT client AS subject,
                  COUNT(DISTINCT host) AS count,
                  MAX(host) AS sample
             FROM access_log
            WHERE ts >= @from AND ts < @to AND client != ''
            GROUP BY client
           HAVING count >= @threshold
            ORDER BY count DESC
            LIMIT ${SUBJECT_CAP}`,
        )
        .all({ from, to, threshold: cfg.threshold ?? 5 }) as unknown as Row[];
      return rows.map((r) => ({
        subject: r.subject,
        count: r.count,
        sample: r.sample ?? undefined,
        detail: `Hit ${r.count} distinct hosts in the window`,
      }));
    },
  },
  {
    id: "fuzzing",
    title: "Path fuzzing",
    description:
      "A client requesting many distinct paths that returned errors, typical of directory or parameter fuzzing.",
    defaults: { enabled: true, severity: "high", threshold: 40 },
    editable: { threshold: true, patterns: false },
    run: (db, from, to, cfg) => {
      const rows = db
        .prepare(
          `SELECT client AS subject,
                  COUNT(DISTINCT uri) AS count,
                  MAX(uri) AS sample
             FROM access_log
            WHERE ts >= @from AND ts < @to AND client != '' AND status >= 400
            GROUP BY client
           HAVING count >= @threshold
            ORDER BY count DESC
            LIMIT ${SUBJECT_CAP}`,
        )
        .all({ from, to, threshold: cfg.threshold ?? 40 }) as unknown as Row[];
      return rows.map((r) => ({
        subject: r.subject,
        count: r.count,
        sample: r.sample ?? undefined,
        detail: `${r.count} distinct failing paths in the window`,
      }));
    },
  },
  {
    id: "fallbackProbe",
    title: "Direct-IP / unknown-host probing",
    description:
      "Requests landing on the fallback host (no matching domain), which usually means someone is poking your server by IP.",
    defaults: { enabled: true, severity: "medium", threshold: 20 },
    editable: { threshold: true, patterns: false },
    run: (db, from, to, cfg) =>
      byClient(db, from, to, "host_id IS NULL", {}, cfg.threshold ?? 20),
  },
  {
    id: "methodAnomaly",
    title: "Unusual HTTP methods",
    description:
      "Requests using rare or dangerous methods (CONNECT, TRACE, PROPFIND, DEBUG), often used for probing.",
    defaults: { enabled: true, severity: "medium", threshold: 1 },
    editable: { threshold: true, patterns: false },
    run: (db, from, to, cfg) =>
      byClient(
        db,
        from,
        to,
        "method NOT IN ('GET','POST','HEAD','PUT','PATCH','DELETE','OPTIONS')",
        {},
        cfg.threshold ?? 1,
      ),
  },
  {
    id: "error5xxSurge",
    title: "5xx error surge",
    description:
      "A spike in server errors across the deployment, which can accompany an exploitation attempt.",
    defaults: { enabled: true, severity: "medium", threshold: 50 },
    editable: { threshold: true, patterns: false },
    run: (db, from, to, cfg) => {
      const row = db
        .prepare(
          `SELECT COUNT(*) AS count, MAX(uri) AS sample
             FROM access_log
            WHERE ts >= @from AND ts < @to AND status >= 500`,
        )
        .get({ from, to }) as unknown as { count: number; sample: string | null };
      if (!row || row.count < (cfg.threshold ?? 50)) return [];
      return [
        {
          subject: "global",
          count: row.count,
          sample: row.sample ?? undefined,
          detail: `${row.count} server errors (5xx) in the window`,
        },
      ];
    },
  },
];

export const DETECTOR_BY_ID = new Map(DETECTORS.map((d) => [d.id, d]));

/** Default config built from the detector registry. */
export function defaultConfig(): import("./types.js").ThreatConfig {
  const rules: Record<string, RuleConfig> = {};
  for (const d of DETECTORS) rules[d.id] = { ...d.defaults };
  return {
    windowMinutes: 10,
    alertEmail: "",
    alertMinSeverity: "critical",
    cooldownMinutes: 30,
    rules,
  };
}
