import { BanStore, isValidBanTarget, type Ban } from "./store.js";
import type { BanEnforcer } from "./enforcer.js";
import {
  classifyIp,
  ipMatchesAny,
  ipv6Subnet,
  overlapsPrivate,
  prefixLength,
} from "../ingest/networks.js";

// Narrowest prefix a ban may use. Anything wider risks blocking most of the
// internet by typo (e.g. 0.0.0.0/0); a v6 /32 is one ISP-sized allocation.
const MIN_PREFIX_V4 = 8;
const MIN_PREFIX_V6 = 32;

export interface BanResult {
  ok: boolean;
  reason?: string;
}

/**
 * Coordinates the ban list and its enforcement, applying safety rules: never
 * ban a private/Docker address or anything on the threat exception list (so you
 * cannot lock yourself out by trusting your own IP), including via a CIDR that
 * covers one, and never ban an absurdly broad range.
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
    if (!isValidBanTarget(ip)) return { ok: false, reason: "not a valid IP or CIDR" };
    // A bare IPv6 address is widened to its /64: clients rotate privacy
    // addresses within that prefix, so a single-address ban does nothing.
    // Use an explicit "addr/128" to ban one address only. The checks below
    // run on the widened range, since that is what nginx will deny.
    const target = ipv6Subnet(ip.trim()) ?? ip.trim();

    const prefix = prefixLength(target);
    if (prefix && prefix.bits < (prefix.v6 ? MIN_PREFIX_V6 : MIN_PREFIX_V4)) {
      return { ok: false, reason: "range is too broad to ban" };
    }
    if (this.#isException(target)) {
      return { ok: false, reason: "range includes an address on the exception list" };
    }
    if (classifyIp(target) === "private" || overlapsPrivate(target)) {
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
    const target = ip.trim();
    this.#store.remove(target);
    // A bare IPv6 address was stored as its /64 — remove that entry too.
    const net = ipv6Subnet(target);
    if (net) this.#store.remove(net);
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
