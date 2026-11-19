import { ApiError, apiFetch, isMissingEndpoint } from "./client";
import { parseSSEFrame } from "./events";
import { clearStoredSession, getStoredSession, storeSession } from "./session";
import type {
  AnalyticsSecurityEvent,
  AnalyticsSummary,
  AuditEvent,
  AuditQueryFilter,
  BannedIP,
  ClusterTopology,
  CurrentUser,
  CustomRule,
  Exclusion,
  FirewallStatus,
  LearningStats,
  LearningSuggestion,
  LiveStatsFrame,
  ManagedRule,
  MarketplacePackage,
  Metrics,
  PluginMetadata,
  Site,
  Status,
  SystemConfig,
  UserSession,
  WafEvent,
  ZeroTrustPolicy,
} from "./types";

/**
 * The only data source the dashboard has: the control-plane API.
 *
 * There is no mock mode and no "fall back to sample data" branch. Every one of
 * those branches made the UI look alive while it was disconnected — a rule matrix
 * that was not the catalog, bans that were not banned — and they hid the exact
 * failures they should surface.
 *
 * Endpoints marked optional are implemented but not guaranteed on every build
 * (custom rules and learning need a live sidecar). They throw `ApiError` like the
 * rest; callers ask `isMissingEndpoint` when an absent feature is acceptable.
 */
export const wafApi = {
  // -------------------------------------------------------------------------
  // Auth
  // -------------------------------------------------------------------------

  async login(username: string, password: string): Promise<UserSession> {
    const res = await apiFetch<{ token: string; expires_at?: number; role?: string }>(
      "/api/v1/auth/login",
      { method: "POST", body: JSON.stringify({ username, password }) }
    );

    const session: UserSession = {
      token: res.token,
      username,
      // The login response does not carry the role today; /auth/me is the truth
      // and the shell refreshes it right after login.
      role: (res.role as UserSession["role"]) ?? "viewer",
      expires_at: res.expires_at ?? Date.now() + 1000 * 60 * 60 * 8,
    };
    storeSession(session);
    return session;
  },

  getCurrentSession(): UserSession | null {
    return getStoredSession();
  },

  updateStoredRole(role: UserSession["role"]): UserSession | null {
    const current = getStoredSession();
    if (!current) return null;
    const updated: UserSession = { ...current, role };
    storeSession(updated);
    return updated;
  },

  /**
   * Logout is local: the API issues stateless JWTs and has no /auth/logout route.
   */
  async logout(): Promise<void> {
    clearStoredSession();
  },

  /** GET /api/v1/auth/me — who the token actually belongs to. */
  async me(): Promise<CurrentUser> {
    return apiFetch<CurrentUser>("/api/v1/auth/me");
  },

  // -------------------------------------------------------------------------
  // Status, metrics, config & audit
  // -------------------------------------------------------------------------

  async getStatus(): Promise<Status> {
    return apiFetch<Status>("/api/v1/status");
  },

  async getMetrics(): Promise<Metrics> {
    return apiFetch<Metrics>("/api/v1/metrics");
  },

  async getConfig(): Promise<SystemConfig> {
    return apiFetch<SystemConfig>("/api/v1/config");
  },

  async updateConfig(patch: Record<string, unknown>): Promise<void> {
    await apiFetch<{ status: string }>("/api/v1/config", {
      method: "PUT",
      body: JSON.stringify(patch),
    });
  },

  /** The API returns a bare array (up to 100 entries) with optional server filters. */
  async getAudit(filter?: AuditQueryFilter): Promise<AuditEvent[]> {
    const params = new URLSearchParams();
    if (filter?.actor?.trim()) params.set("actor", filter.actor.trim());
    if (filter?.action?.trim()) params.set("action", filter.action.trim());
    if (filter?.result?.trim()) params.set("result", filter.result.trim());
    const qs = params.toString();
    const res = await apiFetch<AuditEvent[] | null>(`/api/v1/audit${qs ? `?${qs}` : ""}`);
    return Array.isArray(res) ? res : [];
  },

  // -------------------------------------------------------------------------
  // Rules
  // -------------------------------------------------------------------------

  /** The managed catalog. Read-only: it is compiled in and immutable at runtime. */
  async getRules(): Promise<ManagedRule[]> {
    const res = await apiFetch<{ rules: ManagedRule[] }>("/api/v1/rules");
    return res.rules ?? [];
  },

  /** Custom rules, proxied to the sidecar. Throws 503 when the engine is absent. */
  async getCustomRules(): Promise<CustomRule[]> {
    const res = await apiFetch<{ rules: CustomRule[] }>("/api/v1/custom-rules");
    return res.rules ?? [];
  },

  async createCustomRule(rule: CustomRule): Promise<CustomRule> {
    return apiFetch<CustomRule>("/api/v1/custom-rules", {
      method: "POST",
      body: JSON.stringify(rule),
    });
  },

  async deleteCustomRule(id: string): Promise<void> {
    await apiFetch<void>(`/api/v1/custom-rules/${encodeURIComponent(id)}`, {
      method: "DELETE",
    });
  },

  // -------------------------------------------------------------------------
  // Firewall & IP bans
  // -------------------------------------------------------------------------

  async getFirewallStatus(): Promise<FirewallStatus> {
    const res = await apiFetch<FirewallStatus>("/api/v1/firewall/rules");
    return {
      enabled: Boolean(res?.enabled),
      backend: res?.backend || "nftables",
      rules: Array.isArray(res?.rules) ? res.rules : [],
    };
  },

  async getBannedIPs(): Promise<BannedIP[]> {
    const status = await this.getFirewallStatus();
    return status.rules;
  },

  async banIP(ip: string, reason: string, ttlSeconds: number): Promise<BannedIP> {
    return apiFetch<BannedIP>("/api/v1/firewall/block", {
      method: "POST",
      body: JSON.stringify({ ip, reason, ttl: ttlSeconds }),
    });
  },

  async unbanIP(ip: string): Promise<void> {
    await apiFetch<void>(`/api/v1/firewall/unblock/${encodeURIComponent(ip)}`, {
      method: "DELETE",
    });
  },

  // -------------------------------------------------------------------------
  // Plugins & Marketplace
  // -------------------------------------------------------------------------

  /** Metadata only. There is no endpoint to enable or disable a plugin. */
  async getPlugins(): Promise<PluginMetadata[]> {
    const res = await apiFetch<PluginMetadata[] | { plugins: PluginMetadata[] }>("/api/v1/plugins");
    return Array.isArray(res) ? res : (res.plugins ?? []);
  },

  async getMarketplace(filter?: {
    category?: string;
    q?: string;
    status?: string;
  }): Promise<MarketplacePackage[]> {
    const params = new URLSearchParams();
    if (filter?.category && filter.category !== "all") params.set("category", filter.category);
    if (filter?.q?.trim()) params.set("q", filter.q.trim());
    if (filter?.status && filter.status !== "all") params.set("status", filter.status);
    const qs = params.toString();
    const res = await apiFetch<MarketplacePackage[] | null>(`/api/v1/marketplace${qs ? `?${qs}` : ""}`);
    return Array.isArray(res) ? res : [];
  },

  async getMarketplaceCategories(): Promise<string[]> {
    const res = await apiFetch<{ categories?: string[] }>("/api/v1/marketplace/categories");
    return res.categories ?? [];
  },

  async installMarketplacePackage(name: string, version = "1.0.0"): Promise<void> {
    await apiFetch<{ status: string }>(
      `/api/v1/marketplace/install/${encodeURIComponent(name)}?version=${encodeURIComponent(version)}`,
      { method: "POST" }
    );
  },

  async uninstallMarketplacePackage(name: string): Promise<void> {
    await apiFetch<{ status: string }>(
      `/api/v1/marketplace/uninstall/${encodeURIComponent(name)}`,
      { method: "DELETE" }
    );
  },

  // -------------------------------------------------------------------------
  // Sites
  // -------------------------------------------------------------------------

  async listSites(): Promise<Site[]> {
    const res = await apiFetch<{ sites: Site[] }>("/api/v1/sites");
    return res.sites ?? [];
  },

  async createSite(site: Site): Promise<Site> {
    return apiFetch<Site>("/api/v1/sites", { method: "POST", body: JSON.stringify(site) });
  },

  async updateSite(host: string, site: Site): Promise<Site> {
    return apiFetch<Site>(`/api/v1/sites/${encodeURIComponent(host)}`, {
      method: "PUT",
      body: JSON.stringify(site),
    });
  },

  async deleteSite(host: string): Promise<void> {
    await apiFetch<void>(`/api/v1/sites/${encodeURIComponent(host)}`, { method: "DELETE" });
  },

  // -------------------------------------------------------------------------
  // Learning (optional: needs the sidecar socket)
  // -------------------------------------------------------------------------

  async getLearningSuggestions(): Promise<LearningSuggestion[]> {
    const res = await apiFetch<{ suggestions: LearningSuggestion[] }>(
      "/api/v1/learning/suggestions"
    );
    return res.suggestions ?? [];
  },

  async getLearningStats(): Promise<LearningStats> {
    return apiFetch<LearningStats>("/api/v1/learning/stats");
  },

  // -------------------------------------------------------------------------
  // Events
  // -------------------------------------------------------------------------

  /**
   * The stored history. The engine keeps a bounded ring, so this is not a log
   * archive: it holds the last 1000 events the API has seen since it started.
   */
  async getEventHistory(limit = 200): Promise<WafEvent[]> {
    const res = await apiFetch<{ events: unknown[] }>(`/api/v1/events/history?limit=${limit}`);
    const out: WafEvent[] = [];
    for (const raw of res.events ?? []) {
      const { event } = parseSSEFrame(JSON.stringify(raw));
      if (event) out.push(event);
    }
    return out;
  },

  /**
   * Streams the live feed.
   *
   * Uses fetch plus a ReadableStream because EventSource cannot send an
   * Authorization header, and putting the token in the URL writes it to the nginx
   * access log.
   *
   * Stops on 401/403 instead of reconnecting forever: retrying a rejected token
   * produces an infinite loop of failed requests and hides the expired session.
   */
  subscribeEvents(
    onEvent: (event: WafEvent) => void,
    onStatus: (connected: boolean) => void,
    onStats?: (stats: LiveStatsFrame) => void,
    onAuthFailure?: () => void
  ): () => void {
    const controller = new AbortController();
    let retryTimer: ReturnType<typeof setTimeout> | null = null;
    let attempt = 0;
    let closed = false;

    const scheduleReconnect = () => {
      if (closed) return;
      attempt += 1;
      const delay = Math.min(30_000, 1_000 * 2 ** Math.min(attempt, 5));
      retryTimer = setTimeout(connect, delay);
    };

    const connect = async () => {
      if (closed) return;
      const session = getStoredSession();
      if (!session?.token) {
        onStatus(false);
        onAuthFailure?.();
        return;
      }

      try {
        const res = await fetch("/api/v1/events", {
          headers: { Accept: "text/event-stream", Authorization: `Bearer ${session.token}` },
          signal: controller.signal,
        });

        if (res.status === 401 || res.status === 403) {
          onStatus(false);
          onAuthFailure?.();
          return;
        }
        if (!res.ok || !res.body) {
          onStatus(false);
          scheduleReconnect();
          return;
        }

        onStatus(true);
        attempt = 0;

        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";

        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });

          let boundary = buffer.indexOf("\n\n");
          while (boundary >= 0) {
            const frame = buffer.slice(0, boundary);
            buffer = buffer.slice(boundary + 2);
            boundary = buffer.indexOf("\n\n");

            for (const line of frame.split("\n")) {
              if (!line.startsWith("data:")) continue;
              const { event, stats } = parseSSEFrame(line.slice(5).trim());
              if (event) onEvent(event);
              if (stats) onStats?.(stats);
            }
          }
        }

        onStatus(false);
        scheduleReconnect();
      } catch (err) {
        if (controller.signal.aborted) return;
        onStatus(false);
        if (err instanceof ApiError && err.isUnauthorized) {
          onAuthFailure?.();
          return;
        }
        scheduleReconnect();
      }
    };

    void connect();

    return () => {
      closed = true;
      controller.abort();
      if (retryTimer) clearTimeout(retryTimer);
    };
  },

  // -------------------------------------------------------------------------
  // Exclusions (False-Positive Tuning)
  // -------------------------------------------------------------------------

  async listExclusions(): Promise<Exclusion[]> {
    const res = await apiFetch<{ exclusions: Exclusion[] }>("/api/v1/exclusions");
    return res.exclusions ?? [];
  },

  async createExclusion(ex: Omit<Exclusion, "id" | "created_at">): Promise<Exclusion> {
    return apiFetch<Exclusion>("/api/v1/exclusions", {
      method: "POST",
      body: JSON.stringify(ex),
    });
  },

  async deleteExclusion(id: string): Promise<void> {
    await apiFetch<void>(`/api/v1/exclusions/${encodeURIComponent(id)}`, {
      method: "DELETE",
    });
  },

  // -------------------------------------------------------------------------
  // Zero-Trust Policies (Envoy ext_authz)
  // -------------------------------------------------------------------------

  async listZeroTrustPolicies(): Promise<ZeroTrustPolicy[]> {
    const res = await apiFetch<{ policies: ZeroTrustPolicy[] }>("/api/v1/zero-trust/policies");
    return res.policies ?? [];
  },

  async createZeroTrustPolicy(policy: Omit<ZeroTrustPolicy, "id" | "created_at" | "updated_at">): Promise<ZeroTrustPolicy> {
    return apiFetch<ZeroTrustPolicy>("/api/v1/zero-trust/policies", {
      method: "POST",
      body: JSON.stringify(policy),
    });
  },

  async updateZeroTrustPolicy(id: string, policy: Partial<ZeroTrustPolicy>): Promise<ZeroTrustPolicy> {
    return apiFetch<ZeroTrustPolicy>(`/api/v1/zero-trust/policies/${encodeURIComponent(id)}`, {
      method: "PUT",
      body: JSON.stringify(policy),
    });
  },

  async deleteZeroTrustPolicy(id: string): Promise<void> {
    await apiFetch<void>(`/api/v1/zero-trust/policies/${encodeURIComponent(id)}`, {
      method: "DELETE",
    });
  },

  // -------------------------------------------------------------------------
  // ClickHouse Analytics & Cluster Topology
  // -------------------------------------------------------------------------

  async getAnalyticsEvents(params?: {
    q?: string;
    action?: string;
    host?: string;
    remote_ip?: string;
    rule_id?: string;
    country?: string;
    since_hours?: number;
    limit?: number;
  }): Promise<{ source: "clickhouse" | "broker"; events: AnalyticsSecurityEvent[] }> {
    const qs = new URLSearchParams();
    if (params?.q) qs.set("q", params.q);
    if (params?.action) qs.set("action", params.action);
    if (params?.host) qs.set("host", params.host);
    if (params?.remote_ip) qs.set("remote_ip", params.remote_ip);
    if (params?.rule_id) qs.set("rule_id", params.rule_id);
    if (params?.country) qs.set("country", params.country);
    if (params?.since_hours) qs.set("since_hours", String(params.since_hours));
    if (params?.limit) qs.set("limit", String(params.limit));
    const suffix = qs.toString() ? `?${qs.toString()}` : "";
    const res = await apiFetch<{ source: "clickhouse" | "broker"; events: AnalyticsSecurityEvent[] }>(
      `/api/v1/analytics/events${suffix}`
    );
    return { source: res.source ?? "broker", events: res.events ?? [] };
  },

  async getAnalyticsSummary(windowHours = 24): Promise<{ source: "clickhouse" | "broker"; summary: AnalyticsSummary }> {
    return apiFetch<{ source: "clickhouse" | "broker"; summary: AnalyticsSummary }>(
      `/api/v1/analytics/summary?window_hours=${windowHours}`
    );
  },

  async getClusterTopology(): Promise<ClusterTopology> {
    return apiFetch<ClusterTopology>("/api/v1/cluster/topology");
  },
};

export { ApiError, isMissingEndpoint };
