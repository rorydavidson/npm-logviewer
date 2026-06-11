/**
 * The enclosing /64 of an IPv6 address as a CIDR string, or the input
 * unchanged for IPv4 / non-address strings. Trusting or banning a single
 * IPv6 address is pointless — privacy extensions rotate addresses within
 * the /64 — so UI actions on IPv6 subjects operate on the whole prefix.
 */
export function subnet64(ip: string): string {
  if (!ip.includes(":") || ip.includes("/") || ip.includes(".")) return ip;
  const halves = ip.split("::");
  if (halves.length > 2) return ip;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const fill = 8 - head.length - tail.length;
  if (halves.length === 2 ? fill < 1 : head.length !== 8) return ip;
  const groups = [...head, ...Array<string>(fill).fill("0"), ...tail];
  if (groups.some((g) => !/^[0-9a-fA-F]{1,4}$/.test(g))) return ip;
  const prefix = groups
    .slice(0, 4)
    .map((g) => parseInt(g, 16).toString(16))
    .join(":");
  return `${prefix}::/64`;
}
