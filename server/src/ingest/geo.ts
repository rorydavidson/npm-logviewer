import geoip from "geoip-lite";

export interface GeoInfo {
  country: string | null;
  region: string | null;
  city: string | null;
  lat: number | null;
  lon: number | null;
}

const EMPTY: GeoInfo = { country: null, region: null, city: null, lat: null, lon: null };

// Small LRU-ish cache; the same client IPs recur constantly in proxy logs.
const cache = new Map<string, GeoInfo>();
const MAX_CACHE = 50_000;

function isPrivate(ip: string): boolean {
  return (
    ip.startsWith("10.") ||
    ip.startsWith("192.168.") ||
    ip.startsWith("127.") ||
    ip.startsWith("::1") ||
    ip.startsWith("fc") ||
    ip.startsWith("fd") ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
    ip === "-" ||
    ip === ""
  );
}

/**
 * Resolve a client IP to a coarse location using the bundled GeoLite database.
 * Fully offline — no network calls, which keeps the dashboard privacy-first.
 */
export function lookupGeo(ip: string): GeoInfo {
  if (isPrivate(ip)) return EMPTY;
  const cached = cache.get(ip);
  if (cached) return cached;

  const r = geoip.lookup(ip);
  const info: GeoInfo = r
    ? {
        country: r.country || null,
        region: r.region || null,
        city: r.city || null,
        lat: r.ll?.[0] ?? null,
        lon: r.ll?.[1] ?? null,
      }
    : EMPTY;

  if (cache.size >= MAX_CACHE) cache.clear();
  cache.set(ip, info);
  return info;
}
