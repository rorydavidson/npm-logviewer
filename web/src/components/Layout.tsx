import { useEffect, useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { Logo } from "./Logo";
import { api } from "../lib/api";
import { useFetch } from "../lib/useFetch";
import { applyViewMode, getViewMode, setViewMode, type ViewMode } from "../lib/viewMode";
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
  { to: "/threats", label: "Threats", end: false },
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
  const [menuOpen, setMenuOpen] = useState(false);
  const [mode, setMode] = useState<ViewMode>(getViewMode());

  // Keep the viewport in sync with the stored preference on mount.
  useEffect(() => applyViewMode(mode), [mode]);

  const toggleMode = () => {
    const next: ViewMode = mode === "desktop" ? "mobile" : "desktop";
    setViewMode(next);
    setMode(next);
  };

  const setRange = (ms: number) => {
    const now = Date.now();
    setFilters({ ...filters, from: now - ms, to: now });
  };

  const navLinkClass = ({ isActive }: { isActive: boolean }) =>
    `rounded-lg px-3 py-1.5 text-sm transition ${
      isActive ? "bg-gray-800 text-white" : "text-gray-400 hover:text-gray-200"
    }`;

  return (
    <div className="mx-auto flex min-h-full max-w-[1500px] flex-col">
      <header className="sticky top-0 z-10 border-b border-gray-800 bg-[#0b0f17]/90 backdrop-blur">
        <div className="flex items-center gap-3 px-4 py-3 sm:px-5">
          <Logo />

          {/* Inline nav on large screens */}
          <nav className="hidden gap-1 lg:flex">
            {NAV.map((n) => (
              <NavLink key={n.to} to={n.to} end={n.end} className={navLinkClass}>
                {n.label}
              </NavLink>
            ))}
          </nav>

          <div className="ml-auto flex items-center gap-2 text-sm text-gray-400">
            <button
              onClick={toggleMode}
              title="Switch between mobile and desktop layout"
              className="rounded-lg border border-gray-700 px-2.5 py-1 text-xs hover:bg-gray-800"
            >
              {mode === "desktop" ? "Mobile site" : "Desktop site"}
            </button>
            <span className="hidden md:inline">{name}</span>
            <button
              onClick={onLogout}
              className="hidden rounded-lg border border-gray-700 px-2.5 py-1 text-xs hover:bg-gray-800 sm:inline-block"
            >
              Sign out
            </button>
            {/* Hamburger on small screens */}
            <button
              onClick={() => setMenuOpen((o) => !o)}
              aria-label="Toggle menu"
              className="rounded-lg border border-gray-700 p-1.5 lg:hidden"
            >
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                {menuOpen ? (
                  <path d="M6 6l12 12M6 18L18 6" strokeLinecap="round" />
                ) : (
                  <path d="M4 7h16M4 12h16M4 17h16" strokeLinecap="round" />
                )}
              </svg>
            </button>
          </div>
        </div>

        {/* Collapsible nav drawer on small screens */}
        {menuOpen && (
          <nav className="flex flex-col gap-1 border-t border-gray-800/70 px-4 py-2 lg:hidden">
            {NAV.map((n) => (
              <NavLink
                key={n.to}
                to={n.to}
                end={n.end}
                onClick={() => setMenuOpen(false)}
                className={navLinkClass}
              >
                {n.label}
              </NavLink>
            ))}
            <button
              onClick={onLogout}
              className="mt-1 rounded-lg border border-gray-700 px-3 py-1.5 text-left text-sm text-gray-300 hover:bg-gray-800 sm:hidden"
            >
              Sign out{name ? ` (${name})` : ""}
            </button>
          </nav>
        )}

        {/* Filter bar — scrolls horizontally on small screens */}
        <div className="flex items-center gap-2 overflow-x-auto border-t border-gray-800/70 px-4 py-2.5 sm:flex-wrap sm:gap-3 sm:px-5">
          <div className="flex shrink-0 gap-1">
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
            className="shrink-0 rounded-md border border-gray-700 bg-gray-900 px-2 py-1 text-xs text-gray-200"
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
            className="shrink-0 rounded-md border border-gray-700 bg-gray-900 px-2 py-1 text-xs text-gray-200"
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
            className="shrink-0 rounded-md border border-gray-700 bg-gray-900 px-2 py-1 text-xs text-gray-200"
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
            className="w-40 shrink-0 rounded-md border border-gray-700 bg-gray-900 px-2 py-1 text-xs text-gray-200 outline-none focus:border-blue-500 sm:w-44"
          />
        </div>
      </header>

      <main className="flex-1 px-4 py-4 sm:px-5 sm:py-5">
        <Outlet />
      </main>
    </div>
  );
}
