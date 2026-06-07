import type {
  AccessRow,
  CountryStat,
  ErrorRow,
  Filters,
  Meta,
  Overview,
} from "./types";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
  });
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
};
