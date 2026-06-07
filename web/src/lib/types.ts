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

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface RuleConfig {
  enabled: boolean;
  severity: Severity;
  threshold?: number;
  patterns?: string[];
}

export interface ThreatConfig {
  windowMinutes: number;
  alertEmail: string;
  alertMinSeverity: Severity;
  cooldownMinutes: number;
  alertMinFindings: number;
  autoBan: { enabled: boolean; minSeverity: Severity; minFindings: number };
  exceptions: string[];
  rules: Record<string, RuleConfig>;
}

export interface Ban {
  ip: string;
  reason: string;
  rule: string | null;
  auto: boolean;
  createdTs: number;
  country: string | null;
  city: string | null;
}

export interface BansResponse {
  canReload: boolean;
  canWrite: boolean;
  bans: Ban[];
}

export interface DetectorMeta {
  id: string;
  title: string;
  description: string;
  editable: { threshold: boolean; patterns: boolean };
}

export interface Finding {
  id: number;
  rule: string;
  subject: string;
  severity: Severity;
  title: string;
  detail: string;
  hostLabel: string | null;
  sample: string | null;
  count: number;
  firstTs: number;
  lastTs: number;
  acknowledged: boolean;
  country: string | null;
  city: string | null;
  targets?: { hostId: number | null; label: string; count: number }[];
}

export interface ThreatsResponse {
  counts: Record<Severity, number>;
  findings: Finding[];
}

export interface ThreatConfigResponse {
  config: ThreatConfig;
  emailConfigured: boolean;
  detectors: DetectorMeta[];
}

export interface Filters {
  from: number;
  to: number;
  hostId: string; // "all" | "fallback" | numeric id as string
  statusClass?: string;
  method?: string;
  search?: string;
  country?: string;
  client?: string;
}
