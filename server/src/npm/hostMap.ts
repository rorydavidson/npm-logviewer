import type { NpmDb } from "./npmDb.js";
import type { ProxyHost } from "../types.js";

/**
 * In-memory cache of NPM proxy hosts, refreshed periodically so newly created
 * or renamed hosts show up without a restart.
 */
export class HostMap {
  #byId = new Map<number, ProxyHost>();
  #npm: NpmDb;
  #timer: NodeJS.Timeout | null = null;

  constructor(npm: NpmDb) {
    this.#npm = npm;
  }

  refresh(): void {
    const hosts = this.#npm.listProxyHosts();
    const next = new Map<number, ProxyHost>();
    for (const h of hosts) next.set(h.id, h);
    this.#byId = next;
  }

  startAutoRefresh(intervalMs = 60_000): void {
    this.refresh();
    this.#timer = setInterval(() => this.refresh(), intervalMs);
    this.#timer.unref();
  }

  stop(): void {
    if (this.#timer) clearInterval(this.#timer);
    this.#timer = null;
  }

  get(id: number): ProxyHost | undefined {
    return this.#byId.get(id);
  }

  /** Human-friendly label for a host id from a log filename. */
  label(id: number | null): string {
    if (id === null) return "fallback";
    const h = this.#byId.get(id);
    if (!h) return `host-${id}`;
    return h.domainNames[0] ?? `host-${id}`;
  }

  all(): ProxyHost[] {
    return [...this.#byId.values()];
  }
}
