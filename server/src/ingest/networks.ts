/**
 * Classifies client IPs so we don't geolocate addresses that are not the real
 * visitor. When a site sits behind Cloudflare, NPM logs the Cloudflare edge IP
 * (`$remote_addr`), not the end user, and geolocating an anycast CDN edge is
 * meaningless (and the bundled GeoLite data often gets it plain wrong).
 *
 * Also provides the IP/CIDR matching used by the exception list and ban
 * checker. Both IPv4 and IPv6 ranges are supported: IPv6 clients routinely
 * rotate addresses within their delegated prefix (privacy extensions), so
 * exact-string comparison is useless for them.
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

// Cloudflare published IPv6 ranges (https://www.cloudflare.com/ips-v6).
const CLOUDFLARE_V6 = [
  "2400:cb00::/32",
  "2606:4700::/32",
  "2803:f800::/32",
  "2405:b500::/32",
  "2405:8100::/32",
  "2a06:98c0::/29",
  "2c0f:f248::/32",
];

function ipv4ToLong(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const o = Number(p);
    if (o > 255) return null;
    n = n * 256 + o;
  }
  return n >>> 0;
}

/**
 * Parse an IPv6 address into a 128-bit value. Handles `::` compression and an
 * embedded dotted-IPv4 tail (`::ffff:1.2.3.4`). Returns null if malformed.
 */
function ipv6ToBigInt(ip: string): bigint | null {
  if (!ip.includes(":")) return null;
  const halves = ip.split("::");
  if (halves.length > 2) return null;

  const expand = (part: string): number[] | null => {
    if (part === "") return [];
    const groups = part.split(":");
    const out: number[] = [];
    for (let i = 0; i < groups.length; i++) {
      const g = groups[i]!;
      if (g.includes(".")) {
        // Dotted IPv4 tail occupies the final two 16-bit groups.
        if (i !== groups.length - 1) return null;
        const v4 = ipv4ToLong(g);
        if (v4 === null) return null;
        out.push((v4 >>> 16) & 0xffff, v4 & 0xffff);
      } else {
        if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
        out.push(parseInt(g, 16));
      }
    }
    return out;
  };

  const head = expand(halves[0] ?? "");
  const tail = halves.length === 2 ? expand(halves[1] ?? "") : null;
  if (head === null || (halves.length === 2 && tail === null)) return null;

  let groups: number[];
  if (halves.length === 2) {
    const fill = 8 - head.length - (tail?.length ?? 0);
    if (fill < 1) return null; // "::" must stand for at least one group
    groups = [...head, ...Array<number>(fill).fill(0), ...(tail ?? [])];
  } else {
    if (head.length !== 8) return null;
    groups = head;
  }

  let v = 0n;
  for (const g of groups) v = (v << 16n) | BigInt(g);
  return v;
}

/** Canonical textual form (lowercase, longest zero-run compressed to `::`). */
function ipv6ToString(v: bigint): string {
  const groups: number[] = [];
  for (let i = 7; i >= 0; i--) groups.push(Number((v >> BigInt(i * 16)) & 0xffffn));
  // Find the longest run of zero groups (length >= 2) to compress.
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLen) {
      bestStart = i;
      bestLen = j - i;
    }
    i = j;
  }
  if (bestLen < 2) return groups.map((g) => g.toString(16)).join(":");
  const left = groups.slice(0, bestStart).map((g) => g.toString(16)).join(":");
  const right = groups.slice(bestStart + bestLen).map((g) => g.toString(16)).join(":");
  return `${left}::${right}`;
}

function ipv6Mask(bits: number): bigint {
  if (bits <= 0) return 0n;
  return ((1n << BigInt(bits)) - 1n) << BigInt(128 - bits);
}

/**
 * The enclosing IPv6 subnet of an address as a canonical CIDR string, or null
 * when the input is not a plain IPv6 address. Used to treat one /64 — the
 * standard end-site allocation, within which clients rotate privacy
 * addresses — as a single actor for detection and banning.
 */
export function ipv6Subnet(ip: string, bits = 64): string | null {
  if (ip.includes("/")) return null;
  const v = ipv6ToBigInt(ip);
  if (v === null) return null;
  return `${ipv6ToString(v & ipv6Mask(bits))}/${bits}`;
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

interface Cidr6 {
  base: bigint;
  mask: bigint;
}

function parseCidr6(cidr: string): Cidr6 | null {
  const [ip, bitsStr] = cidr.split("/");
  const base = ipv6ToBigInt(ip ?? "");
  const bits = Number(bitsStr);
  if (base === null || !Number.isInteger(bits) || bits < 0 || bits > 128) return null;
  const mask = ipv6Mask(bits);
  return { base: base & mask, mask };
}

const CLOUDFLARE_CIDRS = CLOUDFLARE_V4.map(parseCidr).filter(
  (c): c is Cidr => c !== null,
);
const CLOUDFLARE_CIDRS_V6 = CLOUDFLARE_V6.map(parseCidr6).filter(
  (c): c is Cidr6 => c !== null,
);

function inAnyCidr(long: number, cidrs: Cidr[]): boolean {
  return cidrs.some((c) => ((long & c.mask) >>> 0) === c.base);
}

function inAnyCidr6(v: bigint, cidrs: Cidr6[]): boolean {
  return cidrs.some((c) => (v & c.mask) === c.base);
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

// ::1 loopback, fc00::/7 unique-local, fe80::/10 link-local.
const PRIVATE_V6 = ["::1/128", "fc00::/7", "fe80::/10"]
  .map(parseCidr6)
  .filter((c): c is Cidr6 => c !== null);

// ::ffff:0:0/96 — IPv4 addresses mapped into IPv6, e.g. "::ffff:1.2.3.4".
const V4_MAPPED = parseCidr6("::ffff:0:0/96")!;

/**
 * True if `ip` matches any entry in a list of exact IPs or CIDR ranges.
 * Both IPv4 and IPv6 ranges are supported; IPv6 comparison is value-based,
 * so differing textual forms of the same address still match.
 */
export function ipMatchesAny(ip: string, entries: string[]): boolean {
  if (!ip) return false;
  const long = ipv4ToLong(ip);
  const v6 = long === null ? ipv6ToBigInt(ip) : null;
  for (const raw of entries) {
    const entry = raw.trim();
    if (!entry) continue;
    if (entry === ip) return true;
    if (entry.includes("/")) {
      if (long !== null) {
        const cidr = parseCidr(entry);
        if (cidr && ((long & cidr.mask) >>> 0) === cidr.base) return true;
      } else if (v6 !== null) {
        const cidr = parseCidr6(entry);
        if (cidr && (v6 & cidr.mask) === cidr.base) return true;
      }
    } else if (v6 !== null && entry.includes(":")) {
      const entryV6 = ipv6ToBigInt(entry);
      if (entryV6 !== null && entryV6 === v6) return true;
    }
  }
  return false;
}

/** Classify a client IP. */
export function classifyIp(ip: string): IpClass {
  if (!ip || ip === "-") return "private";
  const long = ipv4ToLong(ip);
  if (long !== null) {
    if (isPrivateV4(long)) return "private";
    if (inAnyCidr(long, CLOUDFLARE_CIDRS)) return "cloudflare";
    return "public";
  }
  const v6 = ipv6ToBigInt(ip);
  if (v6 === null) return "public"; // not an IP we can range-check
  if ((v6 & V4_MAPPED.mask) === V4_MAPPED.base) {
    // Classify a mapped IPv4 address by its embedded IPv4 value.
    const embedded = Number(v6 & 0xffffffffn) >>> 0;
    if (isPrivateV4(embedded)) return "private";
    if (inAnyCidr(embedded, CLOUDFLARE_CIDRS)) return "cloudflare";
    return "public";
  }
  if (inAnyCidr6(v6, PRIVATE_V6)) return "private";
  if (inAnyCidr6(v6, CLOUDFLARE_CIDRS_V6)) return "cloudflare";
  return "public";
}
