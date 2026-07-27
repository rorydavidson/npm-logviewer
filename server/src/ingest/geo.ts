import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import geoip from "geoip-lite";
import { classifyIp } from "./networks.js";

/**
 * When the bundled GeoLite database was last written, as an ISO date.
 *
 * geoip-lite ships a snapshot frozen at its own publish date and the data ages
 * badly (addresses get reassigned between countries), so the operator should
 * be able to see how old theirs is. Refreshed at image build time when a
 * MaxMind licence key is supplied — see the Dockerfile.
 */
export function geoDataDate(): string | null {
  try {
    const pkg = createRequire(import.meta.url).resolve("geoip-lite");
    const dat = path.join(path.dirname(pkg), "..", "data", "geoip-country.dat");
    return fs.statSync(dat).mtime.toISOString().slice(0, 10);
  } catch {
    return null;
  }
}

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
