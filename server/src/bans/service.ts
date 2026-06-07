import { BanStore, type Ban } from "./store.js";
import type { BanEnforcer } from "./enforcer.js";
import { classifyIp, ipMatchesAny } from "../ingest/networks.js";

export interface BanResult {
  ok: boolean;
  reason?: string;
}

/**
 * Coordinates the ban list and its enforcement, applying safety rules: never
 * ban a private/Docker address or anything on the threat exception list (so you
 * cannot lock yourself out by trusting your own IP).
 */
export class BanService {
  #store: BanStore;
  #enforcer: BanEnforcer;
  #isException: (ip: string) => boolean;
  #log: (msg: string, extra?: unknown) => void;

  constructor(
    store: BanStore,
    enforcer: BanEnforcer,
    isException: (ip: string) => boolean,
    log: (msg: string, extra?: unknown) => void = () => {},
  ) {
    this.#store = store;
    this.#enforcer = enforcer;
    this.#isException = isException;
    this.#log = log;
  }

  get canReload(): boolean {
    return this.#enforcer.canReload;
  }

  get canWrite(): boolean {
    return this.#enforcer.canWrite;
  }

  list(): Ban[] {
    return this.#store.list();
  }

  async ban(
    ip: string,
    opts: {
      reason?: string;
      rule?: string | null;
      auto?: boolean;
      now: number;
      /** Skip rewriting/reloading nginx now (caller will sync() once). */
      deferSync?: boolean;
    },
  ): Promise<BanResult> {
    const target = ip.trim();
    if (this.#isException(target)) return { ok: false, reason: "IP is on the exception list" };
    // Only refuse to ban plain private addresses (a CIDR is fine).
    if (!target.includes("/") && classifyIp(target) === "private") {
      return { ok: false, reason: "refusing to ban a private address" };
    }
    if (!this.#store.add(target, opts)) {
      return { ok: false, reason: "not a valid IP or CIDR" };
    }
    if (!opts.deferSync) await this.sync();
    if (opts.auto) this.#log("auto-banned IP", { ip: target, rule: opts.rule });
    return { ok: true };
  }

  async unban(ip: string): Promise<void> {
    this.#store.remove(ip.trim());
    await this.sync();
  }

  /** True if this exact IP/CIDR is already banned. */
  has(ip: string): boolean {
    return this.#store.has(ip.trim());
  }

  /**
   * Build a checker that reports whether an IP is covered by the ban list
   * (exact match or within a banned CIDR). Captures the list once, so callers
   * can test many IPs cheaply within a single request.
   */
  checker(): (ip: string) => boolean {
    const ips = this.#store.ips();
    const exact = new Set(ips.filter((i) => !i.includes("/")));
    const cidrs = ips.filter((i) => i.includes("/"));
    return (ip: string) =>
      exact.has(ip) || (cidrs.length > 0 && ipMatchesAny(ip, cidrs));
  }

  /** Re-materialise the nginx snippet from the current list. */
  async sync(): Promise<void> {
    await this.#enforcer.sync(this.#store.ips());
  }
}
