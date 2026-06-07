import { NavLink, Outlet } from "react-router-dom";
import { Logo } from "./Logo";
import { api } from "../lib/api";
import { useFetch } from "../lib/useFetch";
import type { Filters, Meta } from "../lib/types";

const RANGES: { label: string; ms: number }[] = [
  { label: "1h", ms: 3_600_000 },
  { label: "6h", ms: 6 * 3_600_000 },
  { label: "24h", ms: 86_400_000 },
  { label: "7d", ms: 7 * 86_400_000 },
  { label: "30d", ms: 30 * 86_400_000 },
];

const NAV = [
  { to: "/", label: "Overview", end: true },
  { to: "/hosts", label: "Hosts", end: false },
  { to: "/world", label: "World", end: false },
  { to: "/logs", label: "Access logs", end: false },
  { to: "/errors", label: "Errors", end: false },
  { to: "/live", label: "Live tail", end: false },
];

export default function Layout({
  name,
  filters,
  setFilters,
  onLogout,
}: {
  name: string;
  filters: Filters;
  setFilters: (f: Filters) => void;
  onLogout: () => void;
}) {
  const meta = useFetch<Meta>(() => api.meta(), []);
  const activeRange = filters.to - filters.from;

  const setRange = (ms: number) => {
    const now = Date.now();
    setFilters({ ...filters, from: now - ms, to: now });
  };

  return (
    <div className="mx-auto flex min-h-full max-w-[1500px] flex-col">
      <header className="sticky top-0 z-10 border-b border-gray-800 bg-[#0b0f17]/90 backdrop-blur">
        <div className="flex items-center gap-4 px-5 py-3">
          <Logo />
          <nav className="flex gap-1">
            {NAV.map((n) => (
              <NavLink
                key={n.to}
                to={n.to}
                end={n.end}
                className={({ isActive }) =>
                  `rounded-lg px-3 py-1.5 text-sm transition ${
                    isActive
                      ? "bg-gray-800 text-white"
                      : "text-gray-400 hover:text-gray-200"
                  }`
                }
              >
                {n.label}
              </NavLink>
            ))}
          </nav>
          <div className="ml-auto flex items-center gap-3 text-sm text-gray-400">
            <span className="hidden sm:inline">{name}</span>
            <button
              onClick={onLogout}
              className="rounded-lg border border-gray-700 px-2.5 py-1 text-xs hover:bg-gray-800"
            >
              Sign out
            </button>
          </div>
        </div>

        {/* Filter bar */}
        <div className="flex flex-wrap items-center gap-3 border-t border-gray-800/70 px-5 py-2.5">
          <div className="flex gap-1">
            {RANGES.map((r) => (
              <button
                key={r.label}
                onClick={() => setRange(r.ms)}
                className={`rounded-md px-2.5 py-1 text-xs ${
                  Math.abs(activeRange - r.ms) < 60_000
                    ? "bg-blue-600 text-white"
                    : "bg-gray-800 text-gray-300 hover:bg-gray-700"
                }`}
              >
                {r.label}
              </button>
            ))}
          </div>

          <select
            value={filters.hostId}
            onChange={(e) => setFilters({ ...filters, hostId: e.target.value })}
            className="rounded-md border border-gray-700 bg-gray-900 px-2 py-1 text-xs text-gray-200"
          >
            <option value="all">All hosts</option>
            <option value="fallback">Fallback / default</option>
            {meta.data?.hosts.map((h) => (
              <option key={h.id} value={String(h.id)}>
                {h.label}
              </option>
            ))}
          </select>

          <select
            value={filters.statusClass ?? ""}
            onChange={(e) =>
              setFilters({ ...filters, statusClass: e.target.value || undefined })
            }
            className="rounded-md border border-gray-700 bg-gray-900 px-2 py-1 text-xs text-gray-200"
          >
            <option value="">All statuses</option>
            <option value="2">2xx</option>
            <option value="3">3xx</option>
            <option value="4">4xx</option>
            <option value="5">5xx</option>
          </select>

          <select
            value={filters.method ?? ""}
            onChange={(e) =>
              setFilters({ ...filters, method: e.target.value || undefined })
            }
            className="rounded-md border border-gray-700 bg-gray-900 px-2 py-1 text-xs text-gray-200"
          >
            <option value="">All methods</option>
            {["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </select>

          <input
            placeholder="Search path…"
            defaultValue={filters.search ?? ""}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                setFilters({
                  ...filters,
                  search: (e.target as HTMLInputElement).value || undefined,
                });
              }
            }}
            className="w-44 rounded-md border border-gray-700 bg-gray-900 px-2 py-1 text-xs text-gray-200 outline-none focus:border-blue-500"
          />
        </div>
      </header>

      <main className="flex-1 px-5 py-5">
        <Outlet />
      </main>
    </div>
  );
}
