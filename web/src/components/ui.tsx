import type { ReactNode } from "react";

export function Panel({
  title,
  children,
  className = "",
  action,
}: {
  title?: string;
  children: ReactNode;
  className?: string;
  action?: ReactNode;
}) {
  return (
    <div
      className={`rounded-2xl border border-gray-800 bg-gray-900/50 p-4 ${className}`}
    >
      {(title || action) && (
        <div className="mb-3 flex items-center justify-between">
          {title && (
            <h2 className="text-sm font-semibold text-gray-300">{title}</h2>
          )}
          {action}
        </div>
      )}
      {children}
    </div>
  );
}

export function Kpi({
  label,
  value,
  sub,
  accent,
}: {
  label: string;
  value: string;
  sub?: string;
  accent?: string;
}) {
  return (
    <div className="rounded-2xl border border-gray-800 bg-gray-900/50 p-4">
      <div className="text-xs font-medium uppercase tracking-wide text-gray-500">
        {label}
      </div>
      <div
        className="mt-1 text-2xl font-semibold"
        style={{ color: accent ?? "#f3f4f6" }}
      >
        {value}
      </div>
      {sub && <div className="mt-1 text-xs text-gray-500">{sub}</div>}
    </div>
  );
}

/** Horizontal bar list for top-N breakdowns. */
export function BarList({
  rows,
  format,
}: {
  rows: { label: ReactNode; value: number; hint?: string }[];
  format?: (n: number) => string;
}) {
  const max = Math.max(1, ...rows.map((r) => r.value));
  return (
    <div className="space-y-1.5">
      {rows.length === 0 && (
        <div className="py-6 text-center text-sm text-gray-600">No data</div>
      )}
      {rows.map((r, i) => (
        <div key={i} className="group relative">
          <div
            className="absolute inset-y-0 left-0 rounded-md bg-blue-500/15"
            style={{ width: `${(r.value / max) * 100}%` }}
          />
          <div className="relative flex items-center justify-between px-2 py-1 text-sm">
            <span className="truncate pr-2 text-gray-300" title={r.hint}>
              {r.label}
            </span>
            <span className="shrink-0 tabular-nums text-gray-400">
              {format ? format(r.value) : r.value.toLocaleString()}
            </span>
          </div>
        </div>
      ))}
    </div>
  );
}

export function Spinner({ label = "Loading…" }: { label?: string }) {
  return <div className="py-10 text-center text-sm text-gray-500">{label}</div>;
}

export function ErrorBox({ message }: { message: string }) {
  return (
    <div className="rounded-xl border border-red-900/60 bg-red-950/40 p-4 text-sm text-red-300">
      {message}
    </div>
  );
}

const SEV_CLASS: Record<string, string> = {
  critical: "bg-red-500/15 text-red-400 border-red-500/40",
  high: "bg-orange-500/15 text-orange-400 border-orange-500/40",
  medium: "bg-amber-500/15 text-amber-300 border-amber-500/40",
  low: "bg-blue-500/15 text-blue-400 border-blue-500/40",
  info: "bg-gray-500/15 text-gray-400 border-gray-500/40",
};

export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span
      className={`rounded border px-1.5 py-0.5 text-xs font-semibold uppercase ${
        SEV_CLASS[severity] ?? SEV_CLASS.info
      }`}
    >
      {severity}
    </span>
  );
}

export function BannedBadge() {
  return (
    <span
      title="This IP is on the ban list"
      className="rounded bg-red-500/20 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-red-400"
    >
      Banned
    </span>
  );
}

export function StatusBadge({ status }: { status: number }) {
  const cls =
    status >= 500
      ? "bg-red-500/15 text-red-400"
      : status >= 400
        ? "bg-amber-500/15 text-amber-400"
        : status >= 300
          ? "bg-blue-500/15 text-blue-400"
          : "bg-green-500/15 text-green-400";
  return (
    <span className={`rounded px-1.5 py-0.5 text-xs font-medium tabular-nums ${cls}`}>
      {status}
    </span>
  );
}
