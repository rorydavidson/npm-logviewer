import { useEffect, useState } from "react";
import { api } from "../lib/api";
import { useFetch } from "../lib/useFetch";
import { ErrorBox, Panel, Spinner } from "../components/ui";
import { time } from "../lib/format";
import type { ErrorRow, Filters } from "../lib/types";

const PAGE = 100;

function levelColour(level: string): string {
  switch (level) {
    case "emerg":
    case "alert":
    case "crit":
    case "error":
      return "text-red-400";
    case "warn":
      return "text-amber-400";
    default:
      return "text-gray-400";
  }
}

export default function Errors({ filters }: { filters: Filters }) {
  const [offset, setOffset] = useState(0);
  useEffect(() => setOffset(0), [filters]);

  const { data, loading, error } = useFetch(
    () => api.errors(filters, PAGE, offset),
    [filters, offset],
  );

  if (loading && !data) return <Spinner />;
  if (error) return <ErrorBox message={error} />;
  if (!data) return null;

  const end = Math.min(offset + PAGE, data.total);

  return (
    <Panel
      title={`Error log · ${data.total.toLocaleString()} entries`}
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
      <div className="space-y-2">
        {data.rows.map((r: ErrorRow) => (
          <div
            key={r.id}
            className="rounded-lg border border-gray-800 bg-gray-900/40 p-3 text-sm"
          >
            <div className="mb-1 flex items-center gap-3 text-xs">
              <span className="text-gray-500">{time(r.ts)}</span>
              <span className={`font-semibold uppercase ${levelColour(r.level)}`}>
                {r.level}
              </span>
              <span className="text-gray-400">{r.hostLabel}</span>
              {r.client && <span className="text-gray-500">client {r.client}</span>}
            </div>
            <div className="text-gray-200">{r.message}</div>
            {(r.request || r.upstream) && (
              <div className="mt-1 space-y-0.5 text-xs text-gray-500">
                {r.request && <div>request: {r.request}</div>}
                {r.upstream && <div>upstream: {r.upstream}</div>}
              </div>
            )}
          </div>
        ))}
        {data.rows.length === 0 && (
          <div className="py-10 text-center text-gray-600">
            No errors in this range. 🎉
          </div>
        )}
      </div>
    </Panel>
  );
}
