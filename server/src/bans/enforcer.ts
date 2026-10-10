import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { isValidBanTarget } from "./store.js";

// The include path is the NPM container's view of its custom dir, which is
// always /data/nginx/custom regardless of where we mount it.
const BAN_FILENAME = "proxylogs-bans.conf";
const NPM_INCLUDE_PATH = `/data/nginx/custom/${BAN_FILENAME}`;
const INCLUDE_LINE = `include ${NPM_INCLUDE_PATH}; # proxylogs-bans`;

const BLOCKED_FILENAME = "proxylogs-blocked-paths.conf";
const BLOCKED_INCLUDE_PATH = `/data/nginx/custom/${BLOCKED_FILENAME}`;
const BLOCKED_INCLUDE_LINE = `include ${BLOCKED_INCLUDE_PATH}; # proxylogs-blocked-paths`;

export interface EnforcerOpts {
  customDir: string;
  dockerSocket: string;
  npmContainer: string;
  log: (msg: string, extra?: unknown) => void;
}

/**
 * Materialises the ban list as an nginx `deny` snippet inside NPM's custom
 * config directory, ensures NPM includes it in every proxy host, and (if a
 * Docker socket and container name are configured) reloads nginx so the bans
 * take effect immediately.
 */
export class BanEnforcer {
  #opts: EnforcerOpts;

  constructor(opts: EnforcerOpts) {
    this.#opts = opts;
  }

  get canReload(): boolean {
    return Boolean(this.#opts.npmContainer) && fs.existsSync(this.#opts.dockerSocket);
  }

  /** Whether we can actually write the deny file (perms on the custom dir). */
  get canWrite(): boolean {
    try {
      fs.mkdirSync(this.#opts.customDir, { recursive: true });
      fs.accessSync(this.#opts.customDir, fs.constants.W_OK);
      return true;
    } catch {
      return false;
    }
  }

  /** Write the deny file from the current list and reload if possible. */
  async sync(ips: string[]): Promise<void> {
    const { customDir, log } = this.#opts;
    try {
      fs.mkdirSync(customDir, { recursive: true });
    } catch (err) {
      log("ban enforce: cannot create custom dir", { customDir, err });
      return;
    }

    const safe = ips.filter(isValidBanTarget);
    const body =
      "# Managed by ProxyLogs — do not edit. Banned client IPs.\n" +
      safe.map((ip) => `deny ${ip};`).join("\n") +
      "\n";

    const target = path.join(customDir, BAN_FILENAME);

    // Skip the write + nginx reload when nothing changed. This avoids reload
    // churn when sync() runs repeatedly (boot, batched auto-bans) with an
    // unchanged list — important under sustained attacks.
    let existing: string | null = null;
    try {
      existing = fs.readFileSync(target, "utf8");
    } catch {
      existing = null;
    }
    this.#ensureInclude(NPM_INCLUDE_PATH, INCLUDE_LINE);
    if (existing === body) return;

    const tmp = `${target}.tmp`;
    try {
      fs.writeFileSync(tmp, body, { mode: 0o644 });
      fs.renameSync(tmp, target);
    } catch (err) {
      log("ban enforce: cannot write ban file", { target, err });
      return;
    }

    await this.#reload();
  }

  /**
   * Write the never-served paths snippet: a regex location returning 444, or
   * an empty (comment-only) file when blocking is off. The file is written
   * before the include is added, since nginx refuses to load a config that
   * includes a missing file. `regex` must come from blockedPathsRegex(), whose
   * character whitelist keeps it from escaping the location directive.
   */
  async syncBlockedPaths(regex: string | null): Promise<void> {
    const { customDir, log } = this.#opts;
    const target = path.join(customDir, BLOCKED_FILENAME);
    const body =
      "# Managed by ProxyLogs — do not edit. Paths never served on this instance.\n" +
      (regex ? `location ~* "${regex}" {\n  return 444;\n}\n` : "");

    let existing: string | null = null;
    try {
      existing = fs.readFileSync(target, "utf8");
    } catch {
      existing = null;
    }
    if (existing !== body) {
      try {
        fs.mkdirSync(customDir, { recursive: true });
        const tmp = `${target}.tmp`;
        fs.writeFileSync(tmp, body, { mode: 0o644 });
        fs.renameSync(tmp, target);
      } catch (err) {
        log("blocked paths: cannot write snippet", { target, err });
        return;
      }
    }
    const included = this.#ensureInclude(BLOCKED_INCLUDE_PATH, BLOCKED_INCLUDE_LINE);
    if (existing !== body || included) await this.#reload();
  }

  /**
   * Make sure NPM's per-host config includes one of our snippets. Returns true
   * when the include line was added just now.
   */
  #ensureInclude(includePath: string, includeLine: string): boolean {
    const { customDir, log } = this.#opts;
    const serverProxy = path.join(customDir, "server_proxy.conf");
    try {
      let current = "";
      if (fs.existsSync(serverProxy)) current = fs.readFileSync(serverProxy, "utf8");
      if (current.includes(includePath)) return false; // already included
      const next =
        (current.trimEnd() ? current.trimEnd() + "\n" : "") + includeLine + "\n";
      fs.writeFileSync(serverProxy, next, { mode: 0o644 });
      log("ban enforce: added include to server_proxy.conf", { includePath });
      return true;
    } catch (err) {
      log("ban enforce: cannot update server_proxy.conf", { serverProxy, err });
      return false;
    }
  }

  /** Reload nginx in the NPM container via the Docker socket, if available. */
  async #reload(): Promise<void> {
    const { npmContainer, log } = this.#opts;
    if (!this.canReload) return;
    try {
      const id = await this.#resolveContainer();
      if (!id) {
        log("ban enforce: NPM container not found", { npmContainer });
        return;
      }
      const exec = await this.#docker<{ Id: string }>(
        "POST",
        `/containers/${encodeURIComponent(id)}/exec`,
        { AttachStdout: true, AttachStderr: true, Cmd: ["nginx", "-s", "reload"] },
      );
      await this.#docker("POST", `/exec/${exec.Id}/start`, { Detach: true, Tty: false });
      log("ban enforce: reloaded nginx", { container: npmContainer });
    } catch (err) {
      log("ban enforce: nginx reload failed", { err });
    }
  }

  /**
   * Resolve the configured value to a real container id. Accepts either the
   * exact container name/id or a Compose *service* name (e.g. "app"), since the
   * service name is usually not the container name.
   */
  async #resolveContainer(): Promise<string | null> {
    const want = this.#opts.npmContainer;
    const list = await this.#docker<
      Array<{ Id: string; Names?: string[]; Labels?: Record<string, string> }>
    >("GET", "/containers/json", null);
    const match = list.find(
      (c) =>
        c.Names?.some((n) => n === `/${want}` || n === want) ||
        c.Labels?.["com.docker.compose.service"] === want,
    );
    return match?.Id ?? null;
  }

  #docker<T = unknown>(method: string, urlPath: string, payload: unknown): Promise<T> {
    const data = payload === null ? "" : JSON.stringify(payload);
    return new Promise<T>((resolve, reject) => {
      const req = http.request(
        {
          socketPath: this.#opts.dockerSocket,
          method,
          path: urlPath,
          headers: data
            ? {
                "Content-Type": "application/json",
                "Content-Length": Buffer.byteLength(data),
              }
            : {},
        },
        (res) => {
          let chunks = "";
          res.on("data", (c) => (chunks += c));
          res.on("end", () => {
            if ((res.statusCode ?? 500) >= 400) {
              reject(new Error(`docker ${res.statusCode}: ${chunks.slice(0, 200)}`));
              return;
            }
            try {
              resolve(chunks ? (JSON.parse(chunks) as T) : ({} as T));
            } catch {
              resolve({} as T);
            }
          });
        },
      );
      req.on("error", reject);
      if (data) req.write(data);
      req.end();
    });
  }
}
