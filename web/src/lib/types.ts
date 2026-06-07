export interface Summary {
  requests: number;
  uniqueVisitors: number;
  totalBytes: number;
  errors: number;
  errorRate: number;
  avgBytes: number;
  class2: number;
  class3: number;
  class4: number;
  class5: number;
}

export interface TimePoint {
  bucket: number;
  total: number;
  class2: number;
  class3: number;
  class4: number;
  class5: number;
  bytes: number;
}

export interface Bucketed {
  key: string;
  count: number;
  bytes?: number;
  country?: string | null;
  city?: string | null;
}

export interface StatusCount {
  status: number;
  count: number;
}

export interface CountryStat {
  country: string;
  count: number;
  uniqueVisitors: number;
  lat: number | null;
  lon: number | null;
}

export interface HostStat {
  hostId: number | null;
  label: string;
  requests: number;
  errors: number;
  bytes: number;
  uniqueVisitors: number;
}

export interface Overview {
  filter: Record<string, unknown>;
  bucketMs: number;
  summary: Summary;
  timeseries: TimePoint[];
  statusBreakdown: StatusCount[];
  methods: Bucketed[];
  topPaths: Bucketed[];
  topClients: Bucketed[];
  topReferers: Bucketed[];
  topUserAgents: Bucketed[];
  geo: CountryStat[];
  perHost: HostStat[];
}

export interface AccessRow {
  id: number;
  hostId: number | null;
  hostLabel: string;
  ts: number;
  status: number;
  method: string;
  host: string;
  uri: string;
  client: string;
  bytes: number;
  country: string | null;
  city: string | null;
  userAgent: string;
  referer: string;
}

export interface ErrorRow {
  id: number;
  hostId: number | null;
  hostLabel: string;
  ts: number;
  level: string;
  message: string;
  client: string | null;
  request: string | null;
  upstream: string | null;
}

export interface HostMeta {
  id: number;
  label: string;
  domainNames: string[];
  enabled: boolean;
  forward: string;
}

export interface Meta {
  bounds: { min: number | null; max: number | null };
  hosts: HostMeta[];
}

export interface Filters {
  from: number;
  to: number;
  hostId: string; // "all" | "fallback" | numeric id as string
  statusClass?: string;
  method?: string;
  search?: string;
  country?: string;
}
