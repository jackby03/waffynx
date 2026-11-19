/**
 * Frozen client-side contracts for the control-plane API.
 *
 * Everything here is checked against the Go structs in this repository; if a field
 * is not sent by the server it does not belong in this file.
 *
 * Two shapes are deliberately separate:
 *   WireWafEvent  — exactly what the engine puts on the socket.
 *   WafEvent      — what the console shows, with fields derived on the client.
 */

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

/** The only event types the data plane publishes today. There is no "allowed". */
export type WireEventType = "blocked" | "rate_limited";

/**
 * A WAF event as the engine sends it.
 *
 * The sidecar publishes into its broker only when the verdict is "block", so the
 * console must never expect an "allowed" series: the backend does not emit one.
 */
export interface WireWafEvent {
  type?: WireEventType | string;
  timestamp: string;
  method: string;
  path: string;
  remote_ip: string;
  rule_id: string;
  reason?: string;
  /** Raw matched fragment, already normalised by the engine. */
  payload?: string;
}

/** A periodic stats frame from the same stream. It is not an event. */
export interface LiveStatsFrame {
  type: "stats";
  timestamp?: string;
  total?: number;
  blocked?: number;
  allowed?: number;
  rate_limited?: number;
  max?: number;
  goroutines?: number;
  heap_mb?: number;
  engine?: string;
}

export type Verdict = "deny" | "allow" | "challenge" | "rate_limited";

/**
 * A WAF event as the console renders it.
 *
 * `action` is derived from `type` because the engine does not send it; the
 * `matched_*` fields are derived from `reason`/`payload` for display and are
 * labelled as such in the drawer.
 */
export interface WafEvent extends WireWafEvent {
  action: Verdict;
  matched_field: string;
  matched_value: string;
}

// ---------------------------------------------------------------------------
// Managed catalog & Custom rules
// ---------------------------------------------------------------------------

export type Severity = "critical" | "high" | "medium" | "low";

/**
 * One signature from the managed catalog (/api/v1/rules).
 *
 * The catalog is immutable while the process runs: there is no enable toggle and
 * no hit counter, because neither exists in internal/catalog.
 */
export interface ManagedRule {
  id: string;
  name: string;
  severity: Severity;
  action: "block" | "log";
  tags: string[];
  fields: string[];
}

/** Custom rules live in the data plane and are mutated through the sidecar. */
export type CustomRuleAction = "block" | "deny" | "log" | "allow";

export interface CustomRule {
  id: string;
  name: string;
  description?: string;
  enabled: boolean;
  priority: number;
  action: CustomRuleAction;
  methods?: string[];
  path_pattern?: string;
  path_exact?: string;
  hosts?: string[];
  ips?: string[];
  ip_cidrs?: string[];
  header_name?: string;
  header_value?: string;
  body_contains?: string;
  query_param?: string;
  query_value?: string;
}

// ---------------------------------------------------------------------------
// Host firewall & WAF-layer IP bans
// ---------------------------------------------------------------------------

/**
 * An IP ban enforced at the WAF layer (sidecar) and optionally mirrored into
 * host nftables/UFW in system mode.
 */
export interface BannedIP {
  ip: string;
  reason: string;
  created_at: string;
  expires_at: string;
  /** TTL in seconds as stored by the API (`json:"ttl"`). */
  ttl: number;
}

/** Full payload of GET /api/v1/firewall/rules. */
export interface FirewallStatus {
  enabled: boolean;
  backend: string;
  rules: BannedIP[];
}

// ---------------------------------------------------------------------------
// Plugins & Marketplace
// ---------------------------------------------------------------------------

/** The plugin phases the engine understands. */
export type PluginPhase = "pre_request" | "post_request" | "pre_response" | "post_response" | "response" | "log";

/** A plugin as /api/v1/plugins returns it: metadata only, never live state. */
export interface PluginMetadata {
  name: string;
  version: string;
  description: string;
  author: string;
  license: string;
  phase: PluginPhase | string;
  priority: number;
  tags?: string[];
  homepage?: string;
}

export type PackageStatus = "published" | "installed" | "pending" | "deprecated";

/** One package from /api/v1/marketplace. */
export interface MarketplacePackage {
  id: string;
  name: string;
  version: string;
  description: string;
  author: string;
  license: string;
  category: string;
  tags: string[];
  downloads: number;
  rating: number;
  status: PackageStatus;
  published_at: string;
  updated_at: string;
  checksum?: string;
  plugin?: PluginMetadata;
}

// ---------------------------------------------------------------------------
// Learning
// ---------------------------------------------------------------------------

export interface LearningSuggestion {
  type: "whitelist" | "blocklist" | "rate_limit" | string;
  pattern: string;
  description: string;
  /** 0..1 */
  confidence: number;
  matches: number;
  sample: string;
}

export interface LearningStats {
  total: number;
  blocked: number;
  allowed: number;
  max: number;
}

// ---------------------------------------------------------------------------
// Sites
// ---------------------------------------------------------------------------

export interface TLSPair {
  cert_file: string;
  key_file: string;
}

export interface PathRule {
  path: string;
  upstream?: string;
}

/** A reverse-proxy site: the object the control plane renders into nginx. */
export interface Site {
  host: string;
  upstream: string;
  tls?: TLSPair;
  paths?: PathRule[];
  plugins?: string[];
  headers?: Record<string, string>;
}

// ---------------------------------------------------------------------------
// Observability & Configuration
// ---------------------------------------------------------------------------

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

/** Redacted configuration returned by GET /api/v1/config. */
export interface SystemConfig {
  name?: string;
  version?: string;
  listen?: string;
  logging?: {
    Level?: string;
    Format?: string;
    Output?: string;
    level?: string;
    format?: string;
    output?: string;
  };
  sidecar?: {
    SocketPath?: string;
    SocketGroup?: string;
    FailOpen?: boolean;
    TimeoutMs?: number;
    EventAPIURL?: string;
    EventTimeoutMs?: number;
    socket_path?: string;
    socket_group?: string;
    fail_open?: boolean;
    timeout_ms?: number;
  };
  nginx?: {
    BinaryPath?: string;
    ConfigPath?: string;
    HTTPListen?: string;
    TLSListen?: string;
    WorkerProcesses?: number;
    WorkerConnections?: number;
    EnableHTTP2?: boolean;
    EnableHTTP3?: boolean;
    binary_path?: string;
    config_path?: string;
    http_listen?: string;
    tls_listen?: string;
    worker_processes?: number;
    worker_connections?: number;
    enable_http2?: boolean;
    enable_http3?: boolean;
  };
  appsec?: {
    enabled?: boolean;
    engine?: string;
    rules_path?: string;
    ml_model_path?: string;
    learning_mode?: boolean;
    timeout_ms?: number;
  };
  gateway?: {
    MaxConnections?: number;
    ReadTimeout?: number;
    WriteTimeout?: number;
    IdleTimeout?: number;
    EnableRateLimiting?: boolean;
    max_connections?: number;
    read_timeout?: number;
    write_timeout?: number;
    idle_timeout?: number;
    enable_rate_limiting?: boolean;
  };
  api?: {
    enabled?: boolean;
    listen?: string;
    auth?: {
      jwt_secret?: string;
      token_ttl?: number;
    };
  };
  routes?: unknown[];
  plugins?: Array<{
    Name?: string;
    Enabled?: boolean;
    Config?: Record<string, unknown>;
    name?: string;
    enabled?: boolean;
    config?: Record<string, unknown>;
  }>;
}

/** One audit record (/api/v1/audit). */
export interface AuditEvent {
  timestamp: string;
  actor: string;
  actor_ip: string;
  action: string;
  resource: string;
  result: string;
  details?: string;
  request_id?: string;
}

export interface AuditQueryFilter {
  actor?: string;
  action?: string;
  result?: string;
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

export type Role = "admin" | "analyst" | "viewer";

export interface UserSession {
  token: string;
  username: string;
  role: Role;
  /** Epoch milliseconds. */
  expires_at: number;
}

/** GET /api/v1/auth/me — the truth about who is logged in. */
export interface CurrentUser {
  username: string;
  role: Role | string;
  scopes: string[];
}

// ---------------------------------------------------------------------------
// Distributed Zero Trust, Exclusions, Analytics & Cluster Topology
// ---------------------------------------------------------------------------

export interface Exclusion {
  id: string;
  name: string;
  rule_id: string;
  host?: string;
  path_exact?: string;
  path_prefix?: string;
  param?: string;
  reason?: string;
  enabled: boolean;
  created_at?: string;
}

export interface ZeroTrustPolicy {
  id: string;
  name: string;
  host?: string;
  path_prefix: string;
  enabled: boolean;
  priority: number;
  require_jwt: boolean;
  allowed_issuers?: string[];
  required_scopes?: string[];
  allowed_cidrs?: string[];
  blocked_countries?: string[];
  require_device_header?: string;
  shadow_mode?: boolean;
  created_at?: string;
  updated_at?: string;
}

export interface AnalyticsSecurityEvent {
  event_id: string;
  timestamp: string;
  node_id: string;
  plane: string;
  action: string;
  stage?: string;
  method: string;
  host: string;
  path: string;
  remote_ip: string;
  country_code?: string;
  user_agent?: string;
  rule_id?: string;
  severity?: string;
  reason?: string;
  status_code: number;
  latency_us: number;
  ml_score?: number;
  zt_subject?: string;
  shadow_mode?: boolean;
  headers?: Record<string, string>;
  body_snippet?: string;
}

export interface AnalyticsSummary {
  window_hours: number;
  total_events: number;
  blocked: number;
  rate_limited: number;
  auth_denied: number;
  shadow_blocked: number;
  unique_ips: number;
  top_rules: Array<{ key: string; count: number }>;
  top_ips: Array<{ key: string; count: number }>;
  top_countries: Array<{ key: string; count: number }>;
  timeline: Array<{ bucket: string; total: number; blocked: number }>;
}

export interface ConnectedEnvoyNode {
  node_id: string;
  connected_at: string;
  streams: number;
}

export interface ClusterTopology {
  mode: "distributed" | "standalone";
  policy_revision: number;
  mtls_enabled: boolean;
  planes: {
    data_plane: {
      pep: string;
      xds_enabled: boolean;
      xds_version: number;
      connected_nodes: ConnectedEnvoyNode[];
      redis_enabled: boolean;
      redis_healthy: boolean;
    };
    control_plane: {
      postgres_enabled: boolean;
      postgres_healthy: boolean;
      policy_revision: number;
    };
    observability_plane: {
      clickhouse_enabled: boolean;
      clickhouse_healthy: boolean;
      nats_enabled: boolean;
    };
  };
}

// ---------------------------------------------------------------------------
// Compatibility aliases
// ---------------------------------------------------------------------------

/** @deprecated Use ManagedRule: there is a single rule concept on the read path. */
export type Rule = ManagedRule;
/** @deprecated Use PluginMetadata: the API exposes metadata, not live state. */
export type PluginItem = PluginMetadata;
