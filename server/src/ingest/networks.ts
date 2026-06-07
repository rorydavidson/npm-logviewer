/**
 * Classifies client IPs so we don't geolocate addresses that are not the real
 * visitor. When a site sits behind Cloudflare, NPM logs the Cloudflare edge IP
 * (`$remote_addr`), not the end user, and geolocating an anycast CDN edge is
 * meaningless (and the bundled GeoLite data often gets it plain wrong).
 */

export type IpClass = "private" | "cloudflare" | "public";

// Cloudflare published IPv4 ranges (https://www.cloudflare.com/ips-v4).
const CLOUDFLARE_V4 = [
  "173.245.48.0/20",
  "103.21.244.0/22",
  "103.22.200.0/22",
  "103.31.4.0/22",
  "141.101.64.0/18",
  "108.162.192.0/18",
  "190.93.240.0/20",
  "188.114.96.0/20",
  "197.234.240.0/22",
  "198.41.128.0/17",
  "162.158.0.0/15",
  "104.16.0.0/13",
  "104.24.0.0/14",
  "172.64.0.0/13",
  "131.0.72.0/22",
];

function ipv4ToLong(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    const o = Number(p);
    if (!Number.isInteger(o) || o < 0 || o > 255) return null;
    n = n * 256 + o;
  }
  return n >>> 0;
}

interface Cidr {
  base: number;
  mask: number;
}

function parseCidr(cidr: string): Cidr | null {
  const [ip, bitsStr] = cidr.split("/");
  const base = ipv4ToLong(ip ?? "");
  const bits = Number(bitsStr);
  if (base === null || !Number.isInteger(bits) || bits < 0 || bits > 32) return null;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return { base: (base & mask) >>> 0, mask };
}

const CLOUDFLARE_CIDRS = CLOUDFLARE_V4.map(parseCidr).filter(
  (c): c is Cidr => c !== null,
);

function inAnyCidr(long: number, cidrs: Cidr[]): boolean {
  return cidrs.some((c) => ((long & c.mask) >>> 0) === c.base);
}

function isPrivateV4(long: number): boolean {
  // 10/8, 172.16/12, 192.168/16, 127/8, 100.64/10 (CGNAT), 169.254/16
  return (
    inAnyCidr(long, [
      { base: ipv4ToLong("10.0.0.0")!, mask: ipv4ToLong("255.0.0.0")! },
      { base: ipv4ToLong("172.16.0.0")!, mask: ipv4ToLong("255.240.0.0")! },
      { base: ipv4ToLong("192.168.0.0")!, mask: ipv4ToLong("255.255.0.0")! },
      { base: ipv4ToLong("127.0.0.0")!, mask: ipv4ToLong("255.0.0.0")! },
      { base: ipv4ToLong("100.64.0.0")!, mask: ipv4ToLong("255.192.0.0")! },
      { base: ipv4ToLong("169.254.0.0")!, mask: ipv4ToLong("255.255.0.0")! },
    ])
  );
}

/**
 * True if `ip` matches any entry in a list of exact IPs or CIDR ranges.
 * Non-IPv4 entries are compared as exact strings (covers IPv6 literals).
 */
export function ipMatchesAny(ip: string, entries: string[]): boolean {
  if (!ip) return false;
  const long = ipv4ToLong(ip);
  for (const raw of entries) {
    const entry = raw.trim();
    if (!entry) continue;
    if (entry === ip) return true;
    if (long !== null && entry.includes("/")) {
      const cidr = parseCidr(entry);
      if (cidr && ((long & cidr.mask) >>> 0) === cidr.base) return true;
    }
  }
  return false;
}

/** Classify a client IP. IPv6 is treated as private/unknown for now. */
export function classifyIp(ip: string): IpClass {
  if (!ip || ip === "-") return "private";
  // IPv6 loopback / unique-local / link-local.
  if (ip === "::1" || /^f[cd]/i.test(ip) || /^fe80:/i.test(ip)) return "private";
  const long = ipv4ToLong(ip);
  if (long === null) return "public"; // non-IPv4 we cannot range-check here
  if (isPrivateV4(long)) return "private";
  if (inAnyCidr(long, CLOUDFLARE_CIDRS)) return "cloudflare";
  return "public";
}
