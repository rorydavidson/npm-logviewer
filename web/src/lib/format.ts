export function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 10 ? 0 : 1)} ${units[i]}`;
}

export function num(n: number): string {
  return n.toLocaleString();
}

export function pct(n: number): string {
  return `${(n * 100).toFixed(1)}%`;
}

export function time(ts: number): string {
  return new Date(ts).toLocaleString();
}

export function shortTime(ts: number, bucketMs: number): string {
  const d = new Date(ts);
  // Use date granularity for buckets a day or larger.
  if (bucketMs >= 86_400_000) {
    return d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
  }
  return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}

const STATUS_COLOURS: Record<number, string> = {
  2: "#22c55e",
  3: "#3b82f6",
  4: "#f59e0b",
  5: "#ef4444",
};

export function statusColour(status: number): string {
  return STATUS_COLOURS[Math.floor(status / 100)] ?? "#9ca3af";
}

/** Convert an ISO 3166-1 alpha-2 country code to its flag emoji. */
export function flag(country: string | null | undefined): string {
  if (!country || country.length !== 2) return "🏳️";
  const A = 0x1f1e6;
  const base = "A".charCodeAt(0);
  const cc = country.toUpperCase();
  return (
    String.fromCodePoint(A + (cc.charCodeAt(0) - base)) +
    String.fromCodePoint(A + (cc.charCodeAt(1) - base))
  );
}

const REGION = new Intl.DisplayNames(undefined, { type: "region" });
export function countryName(code: string | null | undefined): string {
  if (!code) return "Unknown";
  try {
    return REGION.of(code.toUpperCase()) ?? code;
  } catch {
    return code;
  }
}
