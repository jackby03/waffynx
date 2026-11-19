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
    heap_inuse: number;
    gc_pause_ns: number;
    num_gc?: number;
    stack_inuse?: number;
  };
  engine?: {
    engine?: string;
    appsec_enabled?: boolean;
    plugins_count?: number;
  };
}

/** /api/v1/status: process and build information, not dashboard aggregates. */
export interface Status {
  version: string;
  git_commit?: string;
  build_time?: string;
  go_version?: string;
  goroutines?: number;
  memory?: { alloc_mb: number; total_alloc_mb: number };
  config?: {
    name?: string;
    engine?: string;
    appsec_enabled?: boolean;
    plugins_count?: number;
  };
}

/**
 * A rule from the managed catalog, as /api/v1/rules returns it.
 *
 * The catalog is immutable at runtime: there is no per-rule enable toggle and no
 * hit counter, so the view must not pretend otherwise.
 */
export interface Rule {
  id: string;
  name: string;
  severity: "critical" | "high" | "medium" | "low";
  action: "block" | "log";
  tags: string[];
  fields: string[];
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
