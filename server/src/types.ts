/** A single parsed access-log entry. */
export interface AccessEntry {
  /** Proxy-host id taken from the log filename, or null for fallback/dead logs. */
  hostId: number | null;
  /** Source log file basename. */
  source: string;
  /** Epoch milliseconds of the request. */
  ts: number;
  /** HTTP status returned to the client. */
  status: number;
  /** Upstream status, when present (proxy format only). */
  upstreamStatus: number | null;
  /** Upstream cache status (e.g. HIT/MISS), when present. */
  cacheStatus: string | null;
  method: string;
  scheme: string;
  host: string;
  uri: string;
  /** Client IP address. */
  client: string;
  /** Response body size in bytes. */
  bytes: number;
  /** Gzip compression ratio, or null when not compressed. */
  gzip: number | null;
  /** Upstream the request was sent to (proxy format only). */
  sentTo: string | null;
  userAgent: string;
  referer: string;
}

/** A single parsed error-log entry. */
export interface ErrorEntry {
  hostId: number | null;
  source: string;
  ts: number;
  level: string;
  message: string;
  client: string | null;
  server: string | null;
  request: string | null;
  upstream: string | null;
}

/** A proxy host as known to NPM. */
export interface ProxyHost {
  id: number;
  domainNames: string[];
  forwardHost: string;
  forwardPort: number;
  enabled: boolean;
}

/** A minimal NPM user record used for authentication. */
export interface NpmUser {
  id: number;
  name: string;
  email: string;
  /** bcrypt hash from the NPM auth table. */
  passwordHash: string | null;
}
