import geoip from "geoip-lite";
import { classifyIp } from "./networks.js";

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

/**
 * Resolve a client IP to a coarse location using the bundled GeoLite database.
 * Fully offline — no network calls, which keeps the dashboard privacy-first.
 *
 * Private and CDN (Cloudflare) addresses are deliberately not geolocated: when
 * a site is proxied through Cloudflare, NPM logs the Cloudflare edge IP rather
 * than the visitor, so any location for it would be misleading. See README for
 * how to log the real client IP.
 */
export function lookupGeo(ip: string): GeoInfo {
  if (classifyIp(ip) !== "public") return EMPTY;
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
