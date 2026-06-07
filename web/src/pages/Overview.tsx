import {
  Area,
  AreaChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { api } from "../lib/api";
import { useFetch } from "../lib/useFetch";
import { BarList, ErrorBox, Kpi, Panel, Spinner } from "../components/ui";
import {
  bytes,
  countryName,
  flag,
  num,
  pct,
  shortTime,
} from "../lib/format";
import type { Filters, Overview as OverviewData } from "../lib/types";

const CLASS_COLOURS = {
  class2: "#22c55e",
  class3: "#3b82f6",
  class4: "#f59e0b",
  class5: "#ef4444",
} as const;

export default function Overview({ filters }: { filters: Filters }) {
  const { data, loading, error } = useFetch<OverviewData>(
    () => api.overview(filters),
    [filters],
  );

  if (loading) return <Spinner />;
  if (error) return <ErrorBox message={error} />;
  if (!data) return null;

  const s = data.summary;
  const chartData = data.timeseries.map((p) => ({
    ...p,
    label: shortTime(p.bucket, data.bucketMs),
  }));

  const donut = [
    { name: "2xx", value: s.class2, fill: CLASS_COLOURS.class2 },
    { name: "3xx", value: s.class3, fill: CLASS_COLOURS.class3 },
    { name: "4xx", value: s.class4, fill: CLASS_COLOURS.class4 },
    { name: "5xx", value: s.class5, fill: CLASS_COLOURS.class5 },
  ].filter((d) => d.value > 0);

  const geoMax = Math.max(1, ...data.geo.map((g) => g.count));

  return (
    <div className="space-y-4">
      {/* KPIs */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-3 lg:grid-cols-6">
        <Kpi label="Requests" value={num(s.requests)} />
        <Kpi label="Unique visitors" value={num(s.uniqueVisitors)} />
        <Kpi label="Bandwidth" value={bytes(s.totalBytes)} />
        <Kpi
          label="Errors"
          value={num(s.errors)}
          sub={pct(s.errorRate) + " of requests"}
          accent={s.errors > 0 ? "#f87171" : undefined}
        />
        <Kpi label="Avg response" value={bytes(Math.round(s.avgBytes))} />
        <Kpi
          label="Success rate"
          value={pct(s.requests ? s.class2 / s.requests : 0)}
          accent="#34d399"
        />
      </div>

      {/* Traffic over time */}
      <Panel title="Traffic over time">
        <div className="h-72">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={chartData} margin={{ top: 5, right: 10, left: -10, bottom: 0 }}>
              <defs>
                {Object.entries(CLASS_COLOURS).map(([k, c]) => (
                  <linearGradient key={k} id={`g-${k}`} x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor={c} stopOpacity={0.5} />
                    <stop offset="100%" stopColor={c} stopOpacity={0} />
                  </linearGradient>
                ))}
              </defs>
              <XAxis dataKey="label" stroke="#6b7280" fontSize={11} tickLine={false} />
              <YAxis stroke="#6b7280" fontSize={11} tickLine={false} width={40} />
              <Tooltip
                contentStyle={{
                  background: "#111827",
                  border: "1px solid #374151",
                  borderRadius: 8,
                  fontSize: 12,
                }}
              />
              {(["class2", "class3", "class4", "class5"] as const).map((k) => (
                <Area
                  key={k}
                  type="monotone"
                  dataKey={k}
                  stackId="1"
                  stroke={CLASS_COLOURS[k]}
                  fill={`url(#g-${k})`}
                  name={k.replace("class", "") + "xx"}
                />
              ))}
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </Panel>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {/* Status donut */}
        <Panel title="Status codes">
          <div className="flex items-center">
            <div className="h-48 w-1/2">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={donut}
                    dataKey="value"
                    nameKey="name"
                    innerRadius={45}
                    outerRadius={70}
                    paddingAngle={2}
                  >
                    {donut.map((d) => (
                      <Cell key={d.name} fill={d.fill} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      background: "#111827",
                      border: "1px solid #374151",
                      borderRadius: 8,
                      fontSize: 12,
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="w-1/2 space-y-2 text-sm">
              {donut.map((d) => (
                <div key={d.name} className="flex items-center justify-between">
                  <span className="flex items-center gap-2 text-gray-300">
                    <span
                      className="inline-block h-2.5 w-2.5 rounded-sm"
                      style={{ background: d.fill }}
                    />
                    {d.name}
                  </span>
                  <span className="tabular-nums text-gray-400">{num(d.value)}</span>
                </div>
              ))}
            </div>
          </div>
        </Panel>

        {/* Methods */}
        <Panel title="Methods">
          <BarList
            rows={data.methods.map((m) => ({ label: m.key, value: m.count }))}
          />
        </Panel>

        {/* Geo */}
        <Panel title="Top countries">
          <div className="max-h-64 space-y-1.5 overflow-y-auto pr-1">
            {data.geo.length === 0 && (
              <div className="py-6 text-center text-sm text-gray-600">
                No geolocated traffic
              </div>
            )}
            {data.geo.map((g) => (
              <div key={g.country} className="group relative">
                <div
                  className="absolute inset-y-0 left-0 rounded-md bg-emerald-500/15"
                  style={{ width: `${(g.count / geoMax) * 100}%` }}
                />
                <div className="relative flex items-center justify-between px-2 py-1 text-sm">
                  <span className="truncate pr-2 text-gray-300">
                    {flag(g.country)} {countryName(g.country)}
                  </span>
                  <span className="shrink-0 tabular-nums text-gray-400">
                    {num(g.count)}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </Panel>
      </div>

      {/* Top breakdowns */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Panel title="Top paths">
          <BarList
            rows={data.topPaths.map((p) => ({
              label: p.key,
              value: p.count,
              hint: p.key,
            }))}
          />
        </Panel>
        <Panel title="Top clients">
          <BarList
            rows={data.topClients.map((c) => ({
              label: `${flag(c.country)} ${c.key}`,
              value: c.count,
              hint: c.city ?? undefined,
            }))}
          />
        </Panel>
        <Panel title="Top referrers">
          <BarList
            rows={data.topReferers
              .filter((r) => r.key !== "-")
              .map((r) => ({ label: r.key, value: r.count, hint: r.key }))}
          />
        </Panel>
        <Panel title="Top user agents">
          <BarList
            rows={data.topUserAgents.map((u) => ({
              label: u.key,
              value: u.count,
              hint: u.key,
            }))}
          />
        </Panel>
      </div>
    </div>
  );
}
