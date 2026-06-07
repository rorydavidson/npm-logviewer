import type {
  AccessRow,
  BansResponse,
  CountryStat,
  ErrorRow,
  Filters,
  Meta,
  Overview,
  ThreatConfig,
  ThreatConfigResponse,
  ThreatsResponse,
} from "./types";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  // Only set a JSON content-type when there is actually a body, otherwise
  // Fastify rejects bodyless POSTs with FST_ERR_CTP_EMPTY_JSON_BODY.
  const headers: Record<string, string> = { ...(init?.headers as Record<string, string>) };
  if (init?.body != null) headers["Content-Type"] = "application/json";

  const res = await fetch(path, { ...init, headers });
  if (!res.ok) {
    let msg = res.statusText;
    try {
      const body = (await res.json()) as { error?: string };
      if (body.error) msg = body.error;
    } catch {
      /* ignore */
    }
    throw new ApiError(res.status, msg);
  }
  return (await res.json()) as T;
}

/** Build a query string from the active filters, omitting empty values. */
export function filterParams(f: Filters): string {
  const p = new URLSearchParams();
  p.set("from", String(f.from));
  p.set("to", String(f.to));
  if (f.hostId && f.hostId !== "all") p.set("hostId", f.hostId);
  if (f.statusClass) p.set("statusClass", f.statusClass);
  if (f.method) p.set("method", f.method);
  if (f.search) p.set("search", f.search);
  if (f.country) p.set("country", f.country);
  if (f.client) p.set("client", f.client);
  return p.toString();
}

export const api = {
  login: (email: string, password: string) =>
    req<{ ok: boolean; name: string; email: string }>("/api/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),
  logout: () => req<{ ok: boolean }>("/api/logout", { method: "POST" }),
  me: () => req<{ email: string; name: string }>("/api/me"),
  meta: () => req<Meta>("/api/meta"),
  overview: (f: Filters) => req<Overview>(`/api/overview?${filterParams(f)}`),
  geo: (f: Filters) =>
    req<{ countries: CountryStat[] }>(`/api/geo?${filterParams(f)}`),
  logs: (f: Filters, limit: number, offset: number) =>
    req<{ total: number; limit: number; offset: number; rows: AccessRow[] }>(
      `/api/logs?${filterParams(f)}&limit=${limit}&offset=${offset}`,
    ),
  errors: (f: Filters, limit: number, offset: number) =>
    req<{ total: number; limit: number; offset: number; rows: ErrorRow[] }>(
      `/api/errors?${filterParams(f)}&limit=${limit}&offset=${offset}`,
    ),

  threats: (severity?: string, includeAcked = false) => {
    const p = new URLSearchParams();
    if (severity) p.set("severity", severity);
    if (includeAcked) p.set("acked", "1");
    return req<ThreatsResponse>(`/api/threats?${p.toString()}`);
  },
  threatConfig: () => req<ThreatConfigResponse>("/api/threats/config"),
  saveThreatConfig: (config: ThreatConfig) =>
    req<{ ok: boolean }>("/api/threats/config", {
      method: "PUT",
      body: JSON.stringify(config),
    }),
  ackThreat: (id: number) =>
    req<{ ok: boolean }>("/api/threats/ack", {
      method: "POST",
      body: JSON.stringify({ id }),
    }),
  ackAllThreats: () => req<{ ok: boolean }>("/api/threats/ack-all", { method: "POST" }),
  clearThreats: () => req<{ ok: boolean }>("/api/threats/clear", { method: "POST" }),
  testThreatEmail: () =>
    req<{ ok: boolean; error?: string }>("/api/threats/test-email", {
      method: "POST",
    }),

  bans: () => req<BansResponse>("/api/bans"),
  banIp: (ip: string, reason?: string) =>
    req<{ ok: boolean }>("/api/bans", {
      method: "POST",
      body: JSON.stringify({ ip, reason }),
    }),
  unbanIp: (ip: string) =>
    req<{ ok: boolean }>(`/api/bans/${encodeURIComponent(ip)}`, {
      method: "DELETE",
    }),
  syncBans: () =>
    req<{ ok: boolean; canWrite: boolean; canReload: boolean }>("/api/bans/sync", {
      method: "POST",
    }),
};
