import path from "node:path";
import type { AccessEntry, ErrorEntry } from "../types.js";

/**
 * NPM writes two access-log formats (see its nginx conf):
 *
 *   proxy:    [$time_local] $upstream_cache_status $upstream_status $status - \
 *             $request_method $scheme $host "$request_uri" [Client $remote_addr] \
 *             [Length $body_bytes_sent] [Gzip $gzip_ratio] [Sent-to $server] \
 *             "$http_user_agent" "$http_referer"
 *
 *   standard: [$time_local] $status - $request_method $scheme $host "$request_uri" \
 *             [Client $remote_addr] [Length $body_bytes_sent] [Gzip $gzip_ratio] \
 *             "$http_user_agent" "$http_referer"
 *
 * Proxy hosts use the proxy format; we support both for robustness.
 */
const PROXY_RE =
  /^\[([^\]]+)\]\s+(\S+)\s+(\S+)\s+(\d{3})\s+-\s+(\S+)\s+(\S+)\s+(\S+)\s+"([^"]*)"\s+\[Client\s+([^\]]+)\]\s+\[Length\s+([^\]]+)\]\s+\[Gzip\s+([^\]]+)\](?:\s+\[Sent-to\s+([^\]]+)\])?\s+"((?:[^"\\]|\\.)*)"\s+"((?:[^"\\]|\\.)*)"\s*$/;

const STANDARD_RE =
  /^\[([^\]]+)\]\s+(\d{3})\s+-\s+(\S+)\s+(\S+)\s+(\S+)\s+"([^"]*)"\s+\[Client\s+([^\]]+)\]\s+\[Length\s+([^\]]+)\]\s+\[Gzip\s+([^\]]+)\]\s+"((?:[^"\\]|\\.)*)"\s+"((?:[^"\\]|\\.)*)"\s*$/;

const MONTHS: Record<string, number> = {
  Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5,
  Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11,
};

/**
 * Parse an nginx `$time_local` value (`10/Oct/2023:13:55:36 +0000`) to epoch ms.
 * Returns null when the shape is unrecognised.
 */
export function parseTimeLocal(value: string): number | null {
  const m = value.match(
    /^(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s+([+-]\d{4})$/,
  );
  if (!m) return null;
  const [, dd, mon, yyyy, hh, mm, ss, tz] = m;
  const month = MONTHS[mon as string];
  if (month === undefined) return null;
  const sign = (tz as string)[0] === "-" ? -1 : 1;
  const tzH = Number((tz as string).slice(1, 3));
  const tzM = Number((tz as string).slice(3, 5));
  const offsetMs = sign * (tzH * 60 + tzM) * 60_000;
  const utc = Date.UTC(
    Number(yyyy), month, Number(dd),
    Number(hh), Number(mm), Number(ss),
  );
  return utc - offsetMs;
}

function toIntOrNull(value: string): number | null {
  if (value === "-" || value === "") return null;
  const n = Number.parseInt(value, 10);
  return Number.isNaN(n) ? null : n;
}

function toFloatOrNull(value: string): number | null {
  if (value === "-" || value === "") return null;
  const n = Number.parseFloat(value);
  return Number.isNaN(n) ? null : n;
}

function dashToNull(value: string): string | null {
  return value === "-" || value === "" ? null : value;
}

/**
 * Derive the NPM proxy-host id from a log filename.
 * `proxy-host-7_access.log` -> 7. Fallback/dead-host logs -> null.
 */
export function hostIdFromFilename(filename: string): number | null {
  const base = path.basename(filename);
  const m = base.match(/^proxy-host-(\d+)_(?:access|error)\.log$/);
  return m ? Number.parseInt(m[1] as string, 10) : null;
}

/** True for files we treat as access logs. */
export function isAccessLog(filename: string): boolean {
  return /_access\.log(\.\d+)?$/.test(path.basename(filename));
}

/** True for files we treat as error logs. */
export function isErrorLog(filename: string): boolean {
  return /_error\.log(\.\d+)?$/.test(path.basename(filename));
}

/**
 * Parse one access-log line into an AccessEntry, or null if it doesn't match
 * either known format (blank lines, partial writes, custom formats).
 */
export function parseAccessLine(line: string, source: string): AccessEntry | null {
  const trimmed = line.trimEnd();
  if (trimmed === "") return null;
  const hostId = hostIdFromFilename(source);

  const p = PROXY_RE.exec(trimmed);
  if (p) {
    const ts = parseTimeLocal(p[1] as string);
    if (ts === null) return null;
    return {
      hostId,
      source: path.basename(source),
      ts,
      cacheStatus: dashToNull(p[2] as string),
      upstreamStatus: toIntOrNull(p[3] as string),
      status: Number.parseInt(p[4] as string, 10),
      method: p[5] as string,
      scheme: p[6] as string,
      host: p[7] as string,
      uri: p[8] as string,
      client: p[9] as string,
      bytes: toIntOrNull(p[10] as string) ?? 0,
      gzip: toFloatOrNull(p[11] as string),
      sentTo: dashToNull((p[12] as string | undefined) ?? "-"),
      userAgent: p[13] as string,
      referer: p[14] as string,
    };
  }

  const s = STANDARD_RE.exec(trimmed);
  if (s) {
    const ts = parseTimeLocal(s[1] as string);
    if (ts === null) return null;
    return {
      hostId,
      source: path.basename(source),
      ts,
      cacheStatus: null,
      upstreamStatus: null,
      status: Number.parseInt(s[2] as string, 10),
      method: s[3] as string,
      scheme: s[4] as string,
      host: s[5] as string,
      uri: s[6] as string,
      client: s[7] as string,
      bytes: toIntOrNull(s[8] as string) ?? 0,
      gzip: toFloatOrNull(s[9] as string),
      sentTo: null,
      userAgent: s[10] as string,
      referer: s[11] as string,
    };
  }

  return null;
}

const ERROR_RE =
  /^(\d{4})\/(\d{2})\/(\d{2})\s+(\d{2}):(\d{2}):(\d{2})\s+\[(\w+)\]\s+(.*)$/;

/**
 * Parse a standard nginx error-log line. The leading timestamp is in the
 * server's local time; we treat it as UTC since nginx does not record an
 * offset here (good enough for relative ordering and charts).
 */
export function parseErrorLine(line: string, source: string): ErrorEntry | null {
  const trimmed = line.trimEnd();
  if (trimmed === "") return null;
  const m = ERROR_RE.exec(trimmed);
  if (!m) return null;

  const [, yyyy, mon, dd, hh, mm, ss, level, rest] = m;
  const ts = Date.UTC(
    Number(yyyy), Number(mon) - 1, Number(dd),
    Number(hh), Number(mm), Number(ss),
  );

  const body = rest as string;
  const field = (name: string): string | null => {
    const fm = body.match(new RegExp(`${name}: "?([^",]+)"?`));
    return fm ? (fm[1] as string).trim() : null;
  };
  // The message is everything up to the first ", client:" style key.
  const msgEnd = body.search(/,\s+(?:client|server|request|upstream|host):/);
  const rawMessage = msgEnd === -1 ? body : body.slice(0, msgEnd);
  // Drop nginx's internal "PID#TID: *CONN " prefix, keeping the human message.
  const message = rawMessage.replace(/^\d+#\d+:\s*(?:\*\d+\s*)?/, "").trim();

  return {
    hostId: hostIdFromFilename(source),
    source: path.basename(source),
    ts,
    level: level as string,
    message,
    client: field("client"),
    server: field("server"),
    request: field("request"),
    upstream: field("upstream"),
  };
}
