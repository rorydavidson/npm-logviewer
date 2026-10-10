import type { AccessEntry } from "../types.js";
import type { BanService } from "../bans/service.js";
import type { BanEnforcer } from "../bans/enforcer.js";
import { classifyIp, ipMatchesAny } from "../ingest/networks.js";
import type { ThreatConfig } from "./types.js";

/**
 * Paths that are never served on this instance. A request for one is blocked
 * by nginx (444) on every proxy host and, optionally, gets the client banned
 * within seconds of the log line arriving, without waiting for the threat
 * engine's score gate.
 *
 * Pattern format (case-insensitive, matched against the path, not the query):
 *   wp-trackback.php   a file name, in any directory
 *   *.php              an extension, in any directory (`*` stays within one segment)
 *   /wp-admin/*        a path from the root (`*` matches anything, including `/`)
 */

export const DEFAULT_BLOCKED_PATTERNS = ["*.php", "*.asp", "*.aspx", "*.jsp", "*.cgi"];

// Deliberately narrow: these characters cannot break out of the nginx
// `location` regex they are compiled into, and cannot express an
// nginx-config directive.
const ALLOWED = /^[A-Za-z0-9._~\-/*]+$/;
const MAX_LEN = 200;

export function isValidBlockedPattern(p: string): boolean {
  if (!p || p.length > MAX_LEN || !ALLOWED.test(p)) return false;
  // A pattern made only of wildcards and slashes would block every request.
  return /[^*/]/.test(p);
}

/** Compile one pattern to a regex source (no flags). */
export function patternToRegex(p: string): string {
  const rooted = p.startsWith("/");
  const body = p
    .replace(/\./g, "\\.")
    .replace(/\*/g, rooted ? ".*" : "[^/]*");
  return rooted ? `^${body}$` : `/${body}$`;
}

/** Combined regex source for a list of patterns, or null if none are valid. */
export function blockedPathsRegex(patterns: string[]): string | null {
  const parts = patterns.filter(isValidBlockedPattern).map(patternToRegex);
  return parts.length ? `(?:${parts.join("|")})` : null;
}

/**
 * The path nginx would match a location against: query dropped, percent
 * decoding applied, dot segments resolved and repeated slashes merged.
 */
export function requestPath(uri: string): string {
  let p: string;
  try {
    // A leading "//" would otherwise parse as a protocol-relative host.
    p = new URL(uri.replace(/^\/{2,}/, "/"), "http://localhost").pathname;
  } catch {
    p = uri.split("?")[0] ?? uri;
  }
  try {
    p = decodeURIComponent(p);
  } catch {
    // Malformed escapes: match against the raw path.
  }
  return p.replace(/\/{2,}/g, "/");
}

const FLUSH_MS = 2_000;

/**
 * Keeps the nginx block snippet in step with the config and bans clients that
 * request a blocked path as their log lines are ingested.
 */
export class BlockedPaths {
  #getConfig: () => ThreatConfig;
  #bans: BanService;
  #enforcer: BanEnforcer;
  #log: (msg: string, extra?: unknown) => void;
  #cfg: ThreatConfig;
  #match: RegExp | null = null;
  /** Clients waiting to be banned, with the path that triggered it. */
  #pending = new Map<string, string>();
  #timer: NodeJS.Timeout | null = null;

  constructor(
    getConfig: () => ThreatConfig,
    bans: BanService,
    enforcer: BanEnforcer,
    log: (msg: string, extra?: unknown) => void = () => {},
  ) {
    this.#getConfig = getConfig;
    this.#bans = bans;
    this.#enforcer = enforcer;
    this.#log = log;
    this.#cfg = getConfig();
    this.#compile();
  }

  /**
   * Re-read the config (call after it is saved) and rewrite the nginx
   * snippet. The config is cached here because handle() runs per log line.
   */
  async apply(): Promise<void> {
    this.#cfg = this.#getConfig();
    this.#compile();
    const { block, patterns } = this.#cfg.blockedPaths;
    await this.#enforcer.syncBlockedPaths(block ? blockedPathsRegex(patterns) : null);
  }

  #compile(): void {
    const src = blockedPathsRegex(this.#cfg.blockedPaths.patterns);
    this.#match = src ? new RegExp(src, "i") : null;
  }

  matches(uri: string): boolean {
    return this.#match?.test(requestPath(uri)) ?? false;
  }

  /** Inspect one ingested access-log line. */
  handle(e: AccessEntry, now = Date.now()): void {
    const cfg = this.#cfg;
    if (!cfg.blockedPaths.autoBan || !this.#match) return;
    // A restart re-reads recent logs; old hits are history, not live attacks.
    if (e.ts < now - cfg.windowMinutes * 60_000) return;
    if (classifyIp(e.client) !== "public") return;
    if (cfg.exceptions.length && ipMatchesAny(e.client, cfg.exceptions)) return;
    if (!this.matches(e.uri)) return;
    if (this.#pending.has(e.client)) return;
    this.#pending.set(e.client, requestPath(e.uri));
    // Batch bans so a burst of scanners costs one nginx reload, not dozens.
    this.#timer ??= setTimeout(() => void this.flush(), FLUSH_MS);
  }

  async flush(now = Date.now()): Promise<void> {
    if (this.#timer) clearTimeout(this.#timer);
    this.#timer = null;
    const batch = [...this.#pending];
    this.#pending.clear();
    if (!batch.length) return;

    const isBanned = this.#bans.checker();
    let banned = 0;
    for (const [ip, path] of batch) {
      if (isBanned(ip)) continue;
      const r = await this.#bans.ban(ip, {
        reason: `blocked path: ${path.slice(0, 120)}`,
        rule: "blockedPath",
        auto: true,
        now,
        deferSync: true,
      });
      if (r.ok) banned++;
    }
    if (banned) {
      await this.#bans.sync();
      this.#log("banned clients for blocked paths", { banned });
    }
  }

  stop(): void {
    if (this.#timer) clearTimeout(this.#timer);
    this.#timer = null;
  }
}
