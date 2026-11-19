export interface WafEvent {
  /** Server-side discriminator: "blocked", "rate_limited", "stats", ... */
  type?: string;
  reason?: string;
  timestamp: string;
  rule_id: string;
  action: "deny" | "allow" | "challenge" | "rate_limited";
  remote_ip: string;
  method: string;
  path: string;
  matched_field: string;
  matched_value: string;
  anomaly_score?: number;
  country?: string;
  user_agent?: string;
  status_code?: number;
}

export interface Metrics {
  go: {
    goroutines: number;
    heap_alloc: number;
    heap_sys: number;
    gc_pause_ns: number;
  };
  http: {
    requests_total: number;
    blocks_total: number;
    bytes_in: number;
    bytes_out: number;
  };
  engine: {
    latency_p50_us: number;
    latency_p99_us: number;
  };
}

export interface Status {
  version: string;
  uptime_seconds: number;
  rules_count: number;
  plugins_active: number;
  banned_ips_count: number;
  enforcement_mode: "blocking" | "transparent";
  engine_state: "online" | "degraded" | "offline";
}

export interface Rule {
  id: string;
  name: string;
  category: "sqli" | "xss" | "traversal" | "bot" | "cmdinj" | "ml" | "custom";
  severity: "critical" | "high" | "medium" | "low";
  action: "deny" | "challenge" | "log";
  pattern: string;
  hits: number;
  description: string;
  enabled: boolean;
}

export interface BannedIP {
  ip: string;
  reason: string;
  created_at: string;
  expires_at: string;
  ttl_seconds: number;
  packets_dropped?: number;
}

export interface PluginItem {
  id: string;
  name: string;
  version: string;
  author: string;
  category: "core" | "detection" | "mitigation" | "ml";
  description: string;
  enabled: boolean;
  installed: boolean;
  priority: number;
  tags: string[];
}

export interface UserSession {
  token: string;
  username: string;
  role: "admin" | "analyst" | "viewer";
  expires_at: number;
}

/** A reverse-proxy site, as stored by the control plane and rendered into nginx. */
export interface TLSPair {
  cert_file: string;
  key_file: string;
}

export interface PathRule {
  path: string;
  upstream?: string;
}

export interface Site {
  host: string;
  upstream: string;
  tls?: TLSPair;
  paths?: PathRule[];
  plugins?: string[];
  headers?: Record<string, string>;
}
