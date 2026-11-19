/**
 * Frozen client-side contracts for the control-plane API.
 *
 * Everything here is checked against the Go structs in this repository; if a field
 * is not sent by the server it does not belong in this file. The rule exists
 * because the previous contract invented `status_code`, `country`, `hits` and
 * `enabled` fields that no handler ever wrote, and the views then rendered blanks
 * as if the backend were broken.
 *
 * Two shapes are deliberately separate:
 *   WireWafEvent  — exactly what the engine puts on the socket.
 *   WafEvent      — what the console shows, with fields derived on the client.
 * Collapsing them is how "matched value" ended up looking like server data when it
 * was always a guess.
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
// Managed catalog
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
export type CustomRuleAction = "block" | "log" | "allow";

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
// Host bans
// ---------------------------------------------------------------------------

/**
 * An IP ban.
 *
 * Only meaningful in system mode: the ban is applied to the host firewall by
 * waf-agent. In the container there is no NET_ADMIN, so the control plane records
 * the intent and the enforcement point is absent.
 */
export interface BannedIP {
  ip: string;
  reason: string;
  created_at: string;
  expires_at: string;
  /** Seconds remaining, computed by the API at read time. */
  ttl: number;
}

// ---------------------------------------------------------------------------
// Plugins
// ---------------------------------------------------------------------------

/** The plugin phases the engine understands. */
export type PluginPhase = "pre_request" | "post_request" | "response" | "log";

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
// Observability
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
// Compatibility aliases
// ---------------------------------------------------------------------------

/** @deprecated Use ManagedRule: there is a single rule concept on the read path. */
export type Rule = ManagedRule;
/** @deprecated Use PluginMetadata: the API exposes metadata, not live state. */
export type PluginItem = PluginMetadata;
