import { useNavigate } from "react-router-dom";
import { api } from "../lib/api";
import { useFetch } from "../lib/useFetch";
import { ErrorBox, Panel, Spinner } from "../components/ui";
import { bytes, num, pct } from "../lib/format";
import type { Filters, Overview } from "../lib/types";

export default function Hosts({
  filters,
  setFilters,
}: {
  filters: Filters;
  setFilters: (f: Filters) => void;
}) {
  const navigate = useNavigate();
  const { data, loading, error } = useFetch<Overview>(
    () => api.overview(filters),
    [filters],
  );

  const openHost = (hostId: number | null) => {
    setFilters({ ...filters, hostId: hostId === null ? "fallback" : String(hostId) });
    navigate("/");
  };

  if (loading) return <Spinner />;
  if (error) return <ErrorBox message={error} />;
  if (!data) return null;

  const hosts = [...data.perHost].sort((a, b) => b.requests - a.requests);
  const maxReq = Math.max(1, ...hosts.map((h) => h.requests));

  return (
    <Panel title="Proxy hosts">
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead className="text-xs uppercase text-gray-500">
            <tr className="border-b border-gray-800">
              <th className="py-2 pr-3 font-medium">Host</th>
              <th className="py-2 pr-3 text-right font-medium">Requests</th>
              <th className="py-2 pr-3 text-right font-medium">Visitors</th>
              <th className="py-2 pr-3 text-right font-medium">Errors</th>
              <th className="py-2 pr-3 text-right font-medium">Error rate</th>
              <th className="py-2 pr-3 text-right font-medium">Bandwidth</th>
              <th className="py-2 pr-3 font-medium">Share</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800/60">
            {hosts.map((h) => (
              <tr
                key={String(h.hostId)}
                onClick={() => openHost(h.hostId)}
                className="cursor-pointer hover:bg-gray-800/30"
                title={`View dashboard for ${h.label}`}
              >
                <td className="py-2 pr-3 font-medium text-blue-400">{h.label}</td>
                <td className="py-2 pr-3 text-right tabular-nums text-gray-300">
                  {num(h.requests)}
                </td>
                <td className="py-2 pr-3 text-right tabular-nums text-gray-400">
                  {num(h.uniqueVisitors)}
                </td>
                <td className="py-2 pr-3 text-right tabular-nums text-gray-400">
                  {num(h.errors)}
                </td>
                <td
                  className={`py-2 pr-3 text-right tabular-nums ${
                    h.errors / h.requests > 0.05 ? "text-red-400" : "text-gray-400"
                  }`}
                >
                  {pct(h.requests ? h.errors / h.requests : 0)}
                </td>
                <td className="py-2 pr-3 text-right tabular-nums text-gray-400">
                  {bytes(h.bytes)}
                </td>
                <td className="w-40 py-2 pr-3">
                  <div className="h-2 w-full rounded-full bg-gray-800">
                    <div
                      className="h-2 rounded-full bg-blue-500"
                      style={{ width: `${(h.requests / maxReq) * 100}%` }}
                    />
                  </div>
                </td>
              </tr>
            ))}
            {hosts.length === 0 && (
              <tr>
                <td colSpan={7} className="py-10 text-center text-gray-600">
                  No traffic in this range.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}
