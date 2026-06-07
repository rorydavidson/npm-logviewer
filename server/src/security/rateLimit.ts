interface Entry {
  count: number;
  resetAt: number;
}

/**
 * Minimal in-memory fixed-window rate limiter, used to slow down login
 * brute-force attempts. Single-instance only (state is per-process), which
 * matches how this app is deployed. Keyed by client IP.
 */
export class RateLimiter {
  #max: number;
  #windowMs: number;
  #hits = new Map<string, Entry>();

  constructor(max: number, windowMs: number) {
    this.#max = max;
    this.#windowMs = windowMs;
  }

  /** True if the key is currently over the limit. */
  isLimited(key: string, now = Date.now()): boolean {
    const e = this.#hits.get(key);
    if (!e) return false;
    if (now >= e.resetAt) {
      this.#hits.delete(key);
      return false;
    }
    return e.count >= this.#max;
  }

  /** Record one (failed) attempt, returning seconds until the window resets. */
  record(key: string, now = Date.now()): number {
    let e = this.#hits.get(key);
    if (!e || now >= e.resetAt) {
      e = { count: 0, resetAt: now + this.#windowMs };
      this.#hits.set(key, e);
    }
    e.count += 1;
    // Opportunistic cleanup so the map cannot grow without bound.
    if (this.#hits.size > 10_000) this.#prune(now);
    return Math.ceil((e.resetAt - now) / 1000);
  }

  /** Clear a key after a successful login. */
  reset(key: string): void {
    this.#hits.delete(key);
  }

  #prune(now: number): void {
    for (const [k, e] of this.#hits) {
      if (now >= e.resetAt) this.#hits.delete(k);
    }
  }
}
