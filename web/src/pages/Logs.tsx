import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api } from "../lib/api";
import { useFetch } from "../lib/useFetch";
import { ErrorBox, Panel, Spinner, StatusBadge } from "../components/ui";
import { bytes, flag, time } from "../lib/format";
import type { AccessRow, Filters } from "../lib/types";

const PAGE = 100;

export default function Logs({ filters }: { filters: Filters }) {
  const [offset, setOffset] = useState(0);
  const [params, setParams] = useSearchParams();

  // Deep links (e.g. from alert emails) can pre-filter by client and time
  // range via the URL: /logs?client=1.2.3.4&from=...&to=...
  const clientParam = params.get("client") ?? undefined;
  const fromParam = params.get("from");
  const toParam = params.get("to");

  const effective: Filters = useMemo(() => {
    const f = { ...filters };
    if (clientParam) f.client = clientParam;
    if (fromParam) f.from = Number(fromParam);
    if (toParam) f.to = Number(toParam);
    return f;
  }, [filters, clientParam, fromParam, toParam]);

  const clearDeepLink = () => {
    const next = new URLSearchParams(params);
    next.delete("client");
    next.delete("from");
    next.delete("to");
    setParams(next, { replace: true });
  };

  // Reset to the first page whenever the effective filters change.
  useEffect(() => setOffset(0), [effective]);

  const { data, loading, error } = useFetch(
    () => api.logs(effective, PAGE, offset),
    [effective, offset],
  );

  if (loading && !data) return <Spinner />;
  if (error) return <ErrorBox message={error} />;
  if (!data) return null;

  const end = Math.min(offset + PAGE, data.total);

  return (
    <Panel
      title={`Access logs · ${data.total.toLocaleString()} entries`}
      action={
        <div className="flex items-center gap-2 text-xs text-gray-400">
          <span>
            {data.total === 0 ? 0 : offset + 1}–{end}
          </span>
          <button
            disabled={offset === 0}
            onClick={() => setOffset(Math.max(0, offset - PAGE))}
            className="rounded border border-gray-700 px-2 py-1 disabled:opacity-40"
          >
            Prev
          </button>
          <button
            disabled={end >= data.total}
            onClick={() => setOffset(offset + PAGE)}
            className="rounded border border-gray-700 px-2 py-1 disabled:opacity-40"
          >
            Next
          </button>
        </div>
      }
    >
      {clientParam && (
        <div className="mb-3">
          <span className="inline-flex items-center gap-2 rounded-full border border-blue-500/40 bg-blue-500/15 px-3 py-1 text-sm font-medium text-blue-300">
            client {clientParam}
            <button
              onClick={clearDeepLink}
              className="text-blue-400 hover:text-white"
              aria-label="Clear client filter"
            >
              ✕
            </button>
          </span>
        </div>
      )}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead className="text-xs uppercase text-gray-500">
            <tr className="border-b border-gray-800">
              <th className="py-2 pr-3 font-medium">Time</th>
              <th className="py-2 pr-3 font-medium">Host</th>
              <th className="py-2 pr-3 font-medium">Status</th>
              <th className="py-2 pr-3 font-medium">Method</th>
              <th className="py-2 pr-3 font-medium">Path</th>
              <th className="py-2 pr-3 font-medium">Client</th>
              <th className="py-2 pr-3 text-right font-medium">Size</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800/60">
            {data.rows.map((r: AccessRow) => (
              <tr key={r.id} className="hover:bg-gray-800/30">
                <td className="whitespace-nowrap py-1.5 pr-3 text-gray-400">
                  {time(r.ts)}
                </td>
                <td className="py-1.5 pr-3 text-gray-300">{r.hostLabel}</td>
                <td className="py-1.5 pr-3">
                  <StatusBadge status={r.status} />
                </td>
                <td className="py-1.5 pr-3 text-gray-400">{r.method}</td>
                <td
                  className="max-w-[420px] truncate py-1.5 pr-3 text-gray-200"
                  title={r.uri}
                >
                  {r.uri}
                </td>
                <td className="whitespace-nowrap py-1.5 pr-3 text-gray-400">
                  {flag(r.country)} {r.client}
                </td>
                <td className="whitespace-nowrap py-1.5 pr-3 text-right tabular-nums text-gray-400">
                  {bytes(r.bytes)}
                </td>
              </tr>
            ))}
            {data.rows.length === 0 && (
              <tr>
                <td colSpan={7} className="py-10 text-center text-gray-600">
                  No log entries match these filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}
