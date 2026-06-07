import { useCallback, useEffect, useState } from "react";
import { api } from "../lib/api";
import { ErrorBox, Panel, Spinner } from "../components/ui";
import { flag, time } from "../lib/format";
import type { Ban } from "../lib/types";

export default function Bans() {
  const [bans, setBans] = useState<Ban[]>([]);
  const [canReload, setCanReload] = useState(false);
  const [canWrite, setCanWrite] = useState(true);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [newIp, setNewIp] = useState("");
  const [msg, setMsg] = useState<string | null>(null);

  const reload = useCallback(async () => {
    try {
      const r = await api.bans();
      setBans(r.bans);
      setCanReload(r.canReload);
      setCanWrite(r.canWrite);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void reload();
  }, [reload]);

  const flash = (m: string) => {
    setMsg(m);
    setTimeout(() => setMsg(null), 3000);
  };

  const add = async () => {
    const ip = newIp.trim();
    if (!ip) return;
    try {
      await api.banIp(ip, "manual");
      setNewIp("");
      flash(`${ip} banned`);
      void reload();
    } catch (e) {
      flash(e instanceof Error ? `Failed: ${e.message}` : "Failed");
    }
  };

  const unban = async (ip: string) => {
    await api.unbanIp(ip);
    setBans((b) => b.filter((x) => x.ip !== ip));
  };

  const applyNow = async () => {
    const r = await api.syncBans();
    setCanWrite(r.canWrite);
    setCanReload(r.canReload);
    flash(r.canWrite ? "Deny file rewritten from the full list" : "Still can't write the deny file");
  };

  if (loading) return <Spinner />;
  if (error) return <ErrorBox message={error} />;

  return (
    <div className="space-y-4">
      {msg && (
        <div className="rounded-lg border border-teal-500/40 bg-teal-500/15 px-4 py-2 text-sm text-teal-200">
          {msg}
        </div>
      )}

      {!canWrite && (
        <div className="rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-2 text-sm text-red-300">
          Can't write the nginx deny file at the custom-config dir (permission
          denied). Bans are recorded but not enforced. Run the container as root
          (<code className="mx-1">PUID=0 PGID=0</code>) or fix ownership of the
          mounted <code className="mx-1">nginx/custom</code> directory, then they
          will apply.
          <button
            onClick={applyNow}
            className="ml-2 rounded border border-red-700 px-2 py-0.5 text-xs text-red-200 hover:bg-red-900/40"
          >
            Retry now
          </button>
        </div>
      )}

      {canWrite && !canReload && (
        <div className="rounded-lg border border-amber-900/60 bg-amber-950/30 px-4 py-2 text-sm text-amber-300">
          Bans are written to the nginx deny file, but automatic reload is off.
          They apply on NPM's next reload/restart. To apply instantly, set
          <code className="mx-1">NPM_CONTAINER</code> and mount the Docker socket
          (see README).
        </div>
      )}

      <Panel
        title={`Banned IPs · ${bans.length}`}
        action={
          <div className="flex items-center gap-2">
            <input
              value={newIp}
              onChange={(e) => setNewIp(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && add()}
              placeholder="IP or CIDR"
              className="w-40 rounded-md border border-gray-700 bg-gray-900 px-2 py-1 text-xs text-gray-200 outline-none focus:border-blue-500"
            />
            <button
              onClick={add}
              className="rounded-lg bg-red-600/80 px-3 py-1.5 text-xs font-medium text-white hover:bg-red-600"
            >
              Ban
            </button>
          </div>
        }
      >
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="text-xs uppercase text-gray-500">
              <tr className="border-b border-gray-800">
                <th className="py-2 pr-3 font-medium">IP / CIDR</th>
                <th className="py-2 pr-3 font-medium">Source</th>
                <th className="py-2 pr-3 font-medium">Reason</th>
                <th className="py-2 pr-3 font-medium">When</th>
                <th className="py-2 pr-3 font-medium"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/60">
              {bans.map((b) => (
                <tr key={b.ip} className="hover:bg-gray-800/30">
                  <td className="py-2 pr-3 font-mono text-gray-200">
                    {flag(b.country)} {b.ip}
                  </td>
                  <td className="py-2 pr-3">
                    <span
                      className={`rounded px-1.5 py-0.5 text-xs ${
                        b.auto
                          ? "bg-orange-500/15 text-orange-400"
                          : "bg-gray-700/40 text-gray-300"
                      }`}
                    >
                      {b.auto ? "auto" : "manual"}
                    </span>
                  </td>
                  <td className="py-2 pr-3 text-gray-400" title={b.rule ?? undefined}>
                    {b.reason || "—"}
                  </td>
                  <td className="whitespace-nowrap py-2 pr-3 text-gray-500">
                    {time(b.createdTs)}
                  </td>
                  <td className="py-2 pr-3 text-right">
                    <button
                      onClick={() => unban(b.ip)}
                      className="rounded border border-gray-700 px-2 py-0.5 text-xs text-gray-300 hover:bg-gray-800"
                    >
                      Unban
                    </button>
                  </td>
                </tr>
              ))}
              {bans.length === 0 && (
                <tr>
                  <td colSpan={5} className="py-10 text-center text-gray-600">
                    No banned IPs.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}
