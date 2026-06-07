import type { Filter } from "../store/analytics.js";

type Query = Record<string, string | string[] | undefined>;

function num(v: string | string[] | undefined): number | undefined {
  if (typeof v !== "string" || v.trim() === "") return undefined;
  const n = Number(v);
  return Number.isFinite(n) ? n : undefined;
}

function str(v: string | string[] | undefined): string | undefined {
  return typeof v === "string" && v.trim() !== "" ? v : undefined;
}

/**
 * Translate request query parameters into an analytics Filter.
 * Defaults the time range to the last 24h when neither bound is given.
 */
export function parseFilter(q: Query, defaultRangeMs = 86_400_000): Filter {
  const now = Date.now();
  const from = num(q.from);
  const to = num(q.to);

  const filter: Filter = {
    from: from ?? now - defaultRangeMs,
    to: to ?? now,
  };

  // hostId: numeric id, or the literal "fallback" -> null, or "all" -> omit.
  const host = str(q.hostId);
  if (host === "fallback") filter.hostId = null;
  else if (host && host !== "all") {
    const id = Number(host);
    if (Number.isInteger(id)) filter.hostId = id;
  }

  const status = num(q.status);
  if (status !== undefined) filter.status = status;

  const sc = num(q.statusClass);
  if (sc === 2 || sc === 3 || sc === 4 || sc === 5) filter.statusClass = sc;

  const method = str(q.method);
  if (method) filter.method = method.toUpperCase();

  const country = str(q.country);
  if (country) filter.country = country;

  const client = str(q.client);
  if (client) filter.client = client;

  const search = str(q.search);
  if (search) filter.search = search;

  return filter;
}
