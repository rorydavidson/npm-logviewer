import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import { BannedBadge, ErrorBox, Panel, SeverityBadge, Spinner } from "../components/ui";
import { flag, num, time } from "../lib/format";
import { subnet64 } from "../lib/net";
import type {
  DetectorMeta,
  Finding,
  Severity,
  ThreatConfig,
} from "../lib/types";

const SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];

const PAD = 10 * 60 * 1000; // widen the time window a little around the finding

/** Deep link to the access logs for a finding, optionally narrowed to a host. */
function logsHref(f: Finding, hostId?: number | null): string {
  const p = new URLSearchParams({
    client: f.subject,
    from: String(f.firstTs - PAD),
    to: String(f.lastTs + PAD),
  });
  if (hostId !== undefined && hostId !== null) p.set("hostId", String(hostId));
  return `/logs?${p.toString()}`;
}

export default function Threats() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [counts, setCounts] = useState<Record<Severity, number> | null>(null);
  const [detectors, setDetectors] = useState<DetectorMeta[]>([]);
  const [config, setConfig] = useState<ThreatConfig | null>(null);
  const [emailConfigured, setEmailConfigured] = useState(false);
  const [filter, setFilter] = useState<Severity | "">("");
  const [showSettings, setShowSettings] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [toast, setToast] = useState<string | null>(null);

  const reload = useCallback(async () => {
    try {
      const [t, c] = await Promise.all([
        api.threats(filter || undefined),
        api.threatConfig(),
      ]);
      setFindings(t.findings);
      setCounts(t.counts);
      setConfig(c.config);
      setDetectors(c.detectors);
      setEmailConfigured(c.emailConfigured);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load");
    } finally {
      setLoading(false);
    }
  }, [filter]);

  useEffect(() => {
    void reload();
  }, [reload]);

  const flash = (msg: string) => {
    setToast(msg);
    setTimeout(() => setToast(null), 3000);
  };

  const ack = async (id: number) => {
    await api.ackThreat(id);
    setFindings((f) => f.filter((x) => x.id !== id));
  };
  const ackAll = async () => {
    await api.ackAllThreats();
    void reload();
  };
  const clearAll = async () => {
    await api.clearThreats();
    void reload();
  };
  const saveConfig = async () => {
    if (!config) return;
    await api.saveThreatConfig(config);
    flash("Settings saved");
    setTimeout(() => void reload(), 500);
  };
  const testEmail = async () => {
    const r = await api.testThreatEmail();
    flash(r.ok ? "Test email sent" : `Email failed: ${r.error ?? "unknown"}`);
  };
  const trustIp = async (ip: string) => {
    if (!config) return;
    // Trust the whole /64 for IPv6: devices rotate addresses within it.
    const target = subnet64(ip);
    if (config.exceptions.includes(target)) return;
    const next = { ...config, exceptions: [...config.exceptions, target] };
    setConfig(next);
    await api.saveThreatConfig(next);
    flash(`${target} added to exceptions`);
    setTimeout(() => void reload(), 400);
  };
  const banIp = async (ip: string) => {
    try {
      await api.banIp(ip, "manual ban from Threats");
      flash(`${ip} banned`);
      void reload();
    } catch (e) {
      flash(e instanceof Error ? `Ban failed: ${e.message}` : "Ban failed");
    }
  };
  const unbanIp = async (ip: string) => {
    await api.unbanIp(ip);
    flash(`${ip} unbanned`);
    void reload();
  };

  if (loading) return <Spinner />;
  if (error) return <ErrorBox message={error} />;

  return (
    <div className="space-y-4">
      {toast && (
        <div className="rounded-lg border border-teal-500/40 bg-teal-500/15 px-4 py-2 text-sm text-teal-200">
          {toast}
        </div>
      )}

      {/* Summary + actions */}
      <div className="flex flex-wrap items-center gap-3">
        {counts &&
          [...SEVERITIES].reverse().map((s) => (
            <button
              key={s}
              onClick={() => setFilter(filter === s ? "" : s)}
              className={`flex items-center gap-2 rounded-xl border px-3 py-2 text-sm ${
                filter === s ? "border-gray-500 bg-gray-800" : "border-gray-800 bg-gray-900/50"
              }`}
            >
              <SeverityBadge severity={s} />
              <span className="tabular-nums text-gray-300">{num(counts[s])}</span>
            </button>
          ))}
        <div className="ml-auto flex gap-2">
          <button
            onClick={() => void reload()}
            className="rounded-lg border border-gray-700 px-3 py-1.5 text-sm text-gray-300 hover:bg-gray-800"
          >
            Refresh
          </button>
          <button
            onClick={() => setShowSettings((s) => !s)}
            className="rounded-lg border border-gray-700 px-3 py-1.5 text-sm text-gray-300 hover:bg-gray-800"
          >
            {showSettings ? "Hide settings" : "Settings"}
          </button>
          <button
            onClick={ackAll}
            className="rounded-lg border border-gray-700 px-3 py-1.5 text-sm text-gray-300 hover:bg-gray-800"
          >
            Ack all
          </button>
          <button
            onClick={clearAll}
            className="rounded-lg border border-gray-700 px-3 py-1.5 text-sm text-gray-400 hover:bg-gray-800"
          >
            Clear
          </button>
        </div>
      </div>

      {!emailConfigured && (
        <div className="rounded-lg border border-amber-900/60 bg-amber-950/30 px-4 py-2 text-sm text-amber-300">
          Email alerts are off: set <code>RESEND_API_KEY</code> in the container
          environment to enable them.
        </div>
      )}

      {showSettings && config && (
        <SettingsPanel
          config={config}
          detectors={detectors}
          emailConfigured={emailConfigured}
          onChange={setConfig}
          onSave={saveConfig}
          onTestEmail={testEmail}
        />
      )}

      {/* Findings */}
      <Panel title={`Findings${filter ? ` · ${filter}` : ""}`}>
        <div className="space-y-2">
          {findings.length === 0 && (
            <div className="py-10 text-center text-gray-600">
              Nothing suspicious right now. 🛡️
            </div>
          )}
          {findings.map((f) => (
            <div
              key={f.id}
              className="rounded-lg border border-gray-800 bg-gray-900/40 p-3"
            >
              <div className="flex items-center gap-3">
                <SeverityBadge severity={f.severity} />
                <span className="font-medium text-gray-100">{f.title}</span>
                <span className="ml-auto text-xs text-gray-500">
                  last seen {time(f.lastTs)}
                </span>
                {f.subject !== "global" && (
                  <>
                    {f.banned ? (
                      <button
                        onClick={() => unbanIp(f.subject)}
                        title="Remove this IP from the ban list"
                        className="rounded border border-gray-700 px-2 py-0.5 text-xs text-gray-400 hover:bg-gray-800"
                      >
                        Unban
                      </button>
                    ) : (
                      <button
                        onClick={() => banIp(f.subject)}
                        title="Ban this IP (adds an nginx deny rule)"
                        className="rounded border border-red-900/60 px-2 py-0.5 text-xs text-red-400 hover:bg-red-950/40"
                      >
                        Ban IP
                      </button>
                    )}
                    <button
                      onClick={() => trustIp(f.subject)}
                      title="Add this IP to the exception list"
                      className="rounded border border-gray-700 px-2 py-0.5 text-xs text-gray-400 hover:bg-gray-800"
                    >
                      Trust IP
                    </button>
                  </>
                )}
                <button
                  onClick={() => ack(f.id)}
                  className="rounded border border-gray-700 px-2 py-0.5 text-xs text-gray-400 hover:bg-gray-800"
                >
                  Ack
                </button>
              </div>
              <div className="mt-1 flex flex-wrap items-center gap-x-4 gap-y-1 text-sm">
                <span className="text-gray-300">
                  {f.subject === "global" ? (
                    "across all hosts"
                  ) : (
                    <>
                      {flag(f.country)} <span className="font-mono">{f.subject}</span>
                      {f.city ? ` · ${f.city}` : ""}
                      {f.banned && (
                        <span className="ml-2 align-middle">
                          <BannedBadge />
                        </span>
                      )}
                    </>
                  )}
                </span>
                <span className="tabular-nums text-gray-400">{num(f.count)} hits</span>
                {f.subject !== "global" && (
                  <Link
                    to={logsHref(f)}
                    className="ml-auto text-xs text-blue-400 hover:text-blue-300"
                  >
                    View logs →
                  </Link>
                )}
              </div>

              {/* Targeted hosts */}
              {f.targets && f.targets.length > 0 && (
                <div className="mt-1.5 flex flex-wrap items-center gap-1.5 text-xs">
                  <span className="text-gray-500">target:</span>
                  {f.targets.map((t) => (
                    <Link
                      key={String(t.hostId)}
                      to={logsHref(f, t.hostId)}
                      title={`View ${t.label} logs from ${f.subject}`}
                      className="rounded border border-gray-700 bg-gray-800/60 px-1.5 py-0.5 text-gray-300 hover:border-blue-500/50 hover:text-white"
                    >
                      {t.label}
                      <span className="ml-1 tabular-nums text-gray-500">{num(t.count)}</span>
                    </Link>
                  ))}
                </div>
              )}

              <div className="mt-1 text-sm text-gray-400">{f.detail}</div>
              {f.sample && (
                <div className="mt-1 truncate font-mono text-xs text-gray-500" title={f.sample}>
                  e.g. {f.sample}
                </div>
              )}
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}

function SettingsPanel({
  config,
  detectors,
  emailConfigured,
  onChange,
  onSave,
  onTestEmail,
}: {
  config: ThreatConfig;
  detectors: DetectorMeta[];
  emailConfigured: boolean;
  onChange: (c: ThreatConfig) => void;
  onSave: () => void;
  onTestEmail: () => void;
}) {
  const setRule = (id: string, patch: Partial<ThreatConfig["rules"][string]>) =>
    onChange({
      ...config,
      rules: { ...config.rules, [id]: { ...config.rules[id]!, ...patch } },
    });

  return (
    <Panel
      title="Detection settings"
      action={
        <button
          onClick={onSave}
          className="rounded-lg bg-blue-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-blue-500"
        >
          Save
        </button>
      }
    >
      {/* Global settings */}
      <div className="mb-4 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <label className="text-xs text-gray-400">
          Window (minutes)
          <input
            type="number"
            min={1}
            value={config.windowMinutes}
            onChange={(e) => onChange({ ...config, windowMinutes: Number(e.target.value) })}
            className="mt-1 w-full rounded border border-gray-700 bg-gray-950 px-2 py-1 text-sm text-white"
          />
        </label>
        <label className="text-xs text-gray-400">
          Alert email
          <input
            type="email"
            placeholder="you@example.com"
            value={config.alertEmail}
            onChange={(e) => onChange({ ...config, alertEmail: e.target.value })}
            className="mt-1 w-full rounded border border-gray-700 bg-gray-950 px-2 py-1 text-sm text-white"
          />
        </label>
        <label className="text-xs text-gray-400">
          Email at severity ≥
          <select
            value={config.alertMinSeverity}
            onChange={(e) =>
              onChange({ ...config, alertMinSeverity: e.target.value as Severity })
            }
            className="mt-1 w-full rounded border border-gray-700 bg-gray-950 px-2 py-1 text-sm text-white"
          >
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </label>
        <label className="text-xs text-gray-400">
          Cooldown (minutes)
          <input
            type="number"
            min={1}
            value={config.cooldownMinutes}
            onChange={(e) => onChange({ ...config, cooldownMinutes: Number(e.target.value) })}
            className="mt-1 w-full rounded border border-gray-700 bg-gray-950 px-2 py-1 text-sm text-white"
          />
        </label>
        <label className="text-xs text-gray-400">
          Email only after N findings
          <input
            type="number"
            min={1}
            value={config.alertMinFindings}
            onChange={(e) =>
              onChange({ ...config, alertMinFindings: Number(e.target.value) })
            }
            title="1 = email every qualifying threat; higher = only on a concerted attack with multiple findings"
            className="mt-1 w-full rounded border border-gray-700 bg-gray-950 px-2 py-1 text-sm text-white"
          />
        </label>
      </div>
      <div className="mb-4">
        <button
          onClick={onTestEmail}
          disabled={!emailConfigured || !config.alertEmail}
          className="rounded-lg border border-gray-700 px-3 py-1.5 text-sm text-gray-300 hover:bg-gray-800 disabled:opacity-40"
        >
          Send test email
        </button>
      </div>

      {/* Auto-ban */}
      <div className="mb-4 rounded-lg border border-gray-800 p-3">
        <label className="flex items-center gap-2 text-sm font-medium text-gray-200">
          <input
            type="checkbox"
            checked={config.autoBan.enabled}
            onChange={(e) =>
              onChange({
                ...config,
                autoBan: { ...config.autoBan, enabled: e.target.checked },
              })
            }
          />
          Auto-ban attackers
        </label>
        <p className="mt-1 text-xs text-gray-500">
          An IP is banned (nginx deny rule) only when it trips enough distinct
          findings <em>and</em> their combined severity score clears the bar
          (low&nbsp;1 · medium&nbsp;3 · high&nbsp;6 · critical&nbsp;10), so two weak
          signals never ban anyone. IPv6 attackers are banned as their whole /64.
          Trusted/private IPs, and clients with an established history of
          successful traffic (e.g. your own devices), are never auto-banned.
        </p>
        <div className="mt-2 flex flex-wrap gap-4">
          <label className="text-xs text-gray-400">
            Min severity
            <select
              value={config.autoBan.minSeverity}
              onChange={(e) =>
                onChange({
                  ...config,
                  autoBan: { ...config.autoBan, minSeverity: e.target.value as Severity },
                })
              }
              className="mt-1 block rounded border border-gray-700 bg-gray-950 px-2 py-1 text-xs text-white"
            >
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </label>
          <label className="text-xs text-gray-400">
            Distinct findings needed
            <input
              type="number"
              min={1}
              value={config.autoBan.minFindings}
              onChange={(e) =>
                onChange({
                  ...config,
                  autoBan: { ...config.autoBan, minFindings: Number(e.target.value) },
                })
              }
              className="mt-1 block w-24 rounded border border-gray-700 bg-gray-950 px-2 py-1 text-xs text-white"
            />
          </label>
          <label className="text-xs text-gray-400">
            Min combined score
            <input
              type="number"
              min={1}
              value={config.autoBan.minScore}
              onChange={(e) =>
                onChange({
                  ...config,
                  autoBan: { ...config.autoBan, minScore: Number(e.target.value) },
                })
              }
              title="Sum of severity weights across distinct findings (low 1, medium 3, high 6, critical 10). Default 12 = roughly one critical plus one medium."
              className="mt-1 block w-24 rounded border border-gray-700 bg-gray-950 px-2 py-1 text-xs text-white"
            />
          </label>
        </div>
      </div>

      {/* Exception list */}
      <label className="mb-4 block text-xs text-gray-400">
        Trusted IPs / ranges (ignored by all rules) — one per line, exact IP or
        CIDR. IPv6 ranges work too: add your home prefix (e.g. a /56 or /64) to
        cover every device on your network, whatever address it rotates to.
        <textarea
          value={config.exceptions.join("\n")}
          onChange={(e) =>
            onChange({
              ...config,
              exceptions: e.target.value
                .split("\n")
                .map((s) => s.trim())
                .filter(Boolean),
            })
          }
          rows={3}
          spellCheck={false}
          placeholder={"e.g. 203.0.113.5\n10.0.0.0/24\n2a00:23c5:1234::/56"}
          className="mt-1 w-full rounded border border-gray-700 bg-gray-950 px-2 py-1 font-mono text-xs text-gray-200"
        />
      </label>

      {/* Per-rule settings */}
      <div className="space-y-3">
        {detectors.map((d) => {
          const rule = config.rules[d.id];
          if (!rule) return null;
          return (
            <div key={d.id} className="rounded-lg border border-gray-800 p-3">
              <div className="flex items-center gap-3">
                <label className="flex items-center gap-2 text-sm font-medium text-gray-200">
                  <input
                    type="checkbox"
                    checked={rule.enabled}
                    onChange={(e) => setRule(d.id, { enabled: e.target.checked })}
                  />
                  {d.title}
                </label>
                <select
                  value={rule.severity}
                  onChange={(e) => setRule(d.id, { severity: e.target.value as Severity })}
                  className="ml-auto rounded border border-gray-700 bg-gray-950 px-2 py-1 text-xs text-white"
                >
                  {SEVERITIES.map((s) => (
                    <option key={s} value={s}>
                      {s}
                    </option>
                  ))}
                </select>
                {d.editable.threshold && (
                  <label className="flex items-center gap-1 text-xs text-gray-400">
                    threshold
                    <input
                      type="number"
                      min={1}
                      value={rule.threshold ?? 1}
                      onChange={(e) => setRule(d.id, { threshold: Number(e.target.value) })}
                      className="w-20 rounded border border-gray-700 bg-gray-950 px-2 py-1 text-xs text-white"
                    />
                  </label>
                )}
              </div>
              <p className="mt-1 text-xs text-gray-500">{d.description}</p>
              {d.editable.patterns && (
                <textarea
                  value={(rule.patterns ?? []).join("\n")}
                  onChange={(e) =>
                    setRule(d.id, {
                      patterns: e.target.value.split("\n").map((s) => s.trim()).filter(Boolean),
                    })
                  }
                  rows={4}
                  spellCheck={false}
                  className="mt-2 w-full rounded border border-gray-700 bg-gray-950 px-2 py-1 font-mono text-xs text-gray-200"
                  placeholder="One SQL LIKE pattern per line, e.g. %/.env%"
                />
              )}
            </div>
          );
        })}
      </div>
    </Panel>
  );
}
