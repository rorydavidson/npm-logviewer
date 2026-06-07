import type { ComponentProps } from "react";
import WorldMap from "react-svg-worldmap";
import { api } from "../lib/api";
import { useFetch } from "../lib/useFetch";
import { ErrorBox, Kpi, Panel, Spinner } from "../components/ui";
import { countryName, flag, num } from "../lib/format";
import type { CountryStat, Filters } from "../lib/types";

export default function World({
  filters,
  setFilters,
}: {
  filters: Filters;
  setFilters: (f: Filters) => void;
}) {
  const { data, loading, error } = useFetch(() => api.geo(filters), [filters]);

  if (loading) return <Spinner />;
  if (error) return <ErrorBox message={error} />;
  if (!data) return null;

  const countries: CountryStat[] = data.countries;
  // The map lib types `country` as an ISO-code union; our codes come from
  // GeoLite at runtime, so cast through the component's own data prop type.
  type MapData = ComponentProps<typeof WorldMap>["data"];
  const mapData = countries
    .filter((c) => c.country)
    .map((c) => ({ country: c.country.toLowerCase(), value: c.count })) as MapData;

  const totalRequests = countries.reduce((n, c) => n + c.count, 0);
  const maxCount = Math.max(1, ...countries.map((c) => c.count));
  const countryActive = Boolean(filters.country);

  const selectCountry = (code: string) =>
    setFilters({ ...filters, country: code.toUpperCase() });

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-4">
        <div className="grid flex-1 grid-cols-2 gap-4 sm:grid-cols-3">
          <Kpi label="Requests mapped" value={num(totalRequests)} />
          <Kpi label="Countries" value={num(countries.length)} />
          <Kpi
            label="Top country"
            value={
              countries[0]
                ? `${flag(countries[0].country)} ${countryName(countries[0].country)}`
                : "—"
            }
          />
        </div>
        {countryActive && (
          <span className="inline-flex items-center gap-2 rounded-full border border-teal-500/40 bg-teal-500/15 px-3 py-1 text-sm font-medium text-teal-300">
            {flag(filters.country)} {countryName(filters.country)}
            <button
              onClick={() => setFilters({ ...filters, country: undefined })}
              className="text-teal-400 hover:text-white"
              aria-label="Clear country filter"
            >
              ✕
            </button>
          </span>
        )}
      </div>

      <Panel title="Requests by country">
        <div className="flex justify-center overflow-x-auto">
          <WorldMap
            data={mapData}
            size="xl"
            color="#14b8a6"
            backgroundColor="#0b0f17"
            borderColor="#374151"
            strokeOpacity={0.4}
            valueSuffix=" requests"
            tooltipBgColor="#111827"
            tooltipTextColor="#e5e7eb"
            richInteraction
            onClickFunction={(ctx: { countryCode: string }) =>
              selectCountry(ctx.countryCode)
            }
          />
        </div>
        <p className="mt-2 text-center text-xs text-gray-500">
          Click a country to filter the whole dashboard to it.
        </p>
      </Panel>

      <Panel title="Country breakdown">
        <div className="space-y-1.5">
          {countries.length === 0 && (
            <div className="py-6 text-center text-sm text-gray-600">
              No geolocated traffic in this range.
            </div>
          )}
          {countries.map((c) => (
            <button
              key={c.country}
              onClick={() => selectCountry(c.country)}
              className="group relative block w-full text-left"
            >
              <div
                className="absolute inset-y-0 left-0 rounded-md bg-teal-500/15 group-hover:bg-teal-500/25"
                style={{ width: `${(c.count / maxCount) * 100}%` }}
              />
              <div className="relative flex items-center justify-between px-2 py-1.5 text-sm">
                <span className="truncate pr-2 text-gray-200">
                  {flag(c.country)} {countryName(c.country)}
                </span>
                <span className="flex shrink-0 items-center gap-4 tabular-nums text-gray-400">
                  <span title="Unique visitors">{num(c.uniqueVisitors)} ip</span>
                  <span className="text-gray-300">{num(c.count)}</span>
                </span>
              </div>
            </button>
          ))}
        </div>
      </Panel>
    </div>
  );
}
