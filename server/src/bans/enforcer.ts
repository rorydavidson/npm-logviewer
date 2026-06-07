import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { isValidBanTarget } from "./store.js";

// The include path is the NPM container's view of its custom dir, which is
// always /data/nginx/custom regardless of where we mount it.
const BAN_FILENAME = "proxylogs-bans.conf";
const NPM_INCLUDE_PATH = `/data/nginx/custom/${BAN_FILENAME}`;
const INCLUDE_LINE = `include ${NPM_INCLUDE_PATH}; # proxylogs-bans`;

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
    this.#ensureInclude();
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

  /** Make sure NPM's per-host config includes our ban file. */
  #ensureInclude(): void {
    const { customDir, log } = this.#opts;
    const serverProxy = path.join(customDir, "server_proxy.conf");
    try {
      let current = "";
      if (fs.existsSync(serverProxy)) current = fs.readFileSync(serverProxy, "utf8");
      if (current.includes(NPM_INCLUDE_PATH)) return; // already included
      const next =
        (current.trimEnd() ? current.trimEnd() + "\n" : "") + INCLUDE_LINE + "\n";
      fs.writeFileSync(serverProxy, next, { mode: 0o644 });
      log("ban enforce: added include to server_proxy.conf", {});
    } catch (err) {
      log("ban enforce: cannot update server_proxy.conf", { serverProxy, err });
    }
  }

  /** Reload nginx in the NPM container via the Docker socket, if available. */
  async #reload(): Promise<void> {
    const { dockerSocket, npmContainer, log } = this.#opts;
    if (!this.canReload) return;
    try {
      const exec = await this.#docker<{ Id: string }>(
        "POST",
        `/containers/${encodeURIComponent(npmContainer)}/exec`,
        { AttachStdout: true, AttachStderr: true, Cmd: ["nginx", "-s", "reload"] },
      );
      await this.#docker("POST", `/exec/${exec.Id}/start`, { Detach: true, Tty: false });
      log("ban enforce: reloaded nginx", { container: npmContainer });
    } catch (err) {
      log("ban enforce: nginx reload failed", { err });
    }
    void dockerSocket;
  }

  #docker<T = unknown>(method: string, urlPath: string, payload: unknown): Promise<T> {
    const data = JSON.stringify(payload);
    return new Promise<T>((resolve, reject) => {
      const req = http.request(
        {
          socketPath: this.#opts.dockerSocket,
          method,
          path: urlPath,
          headers: {
            "Content-Type": "application/json",
            "Content-Length": Buffer.byteLength(data),
          },
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
      req.write(data);
      req.end();
    });
  }
}
