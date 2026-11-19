import { apiFetch } from "./client";
import type {
  Status, Metrics, Rule, BannedIP, PluginItem, WafEvent, UserSession, Site,
} from "./types";
import {
  MOCK_INITIAL_STATUS,
  MOCK_INITIAL_METRICS,
  MOCK_RULES,
  MOCK_BANNED_IPS,
  MOCK_PLUGINS,
} from "./mock/mockFixtures";
import { mockLogin, getStoredSession, clearSession } from "./mock/mockAuth";
import { getInitialEvents, startMockEventStream } from "./mock/mockEvents";

// Local state for mutable mock fixtures
let mockRules = [...MOCK_RULES];
let mockBanned = [...MOCK_BANNED_IPS];
let mockPlugins = [...MOCK_PLUGINS];
let mockStatus = { ...MOCK_INITIAL_STATUS };

// Determine if we should force mock mode
export function isMockMode(): boolean {
  // If explicitly set in localStorage, obey it
  const forced = localStorage.getItem("waffynx_force_mock");
  if (forced === "true") return true;
  if (forced === "false") return false;
  // Default to mock in Vite dev server (unless proxy is answering)
  return import.meta.env.DEV;
}

export function setForceMock(enabled: boolean): void {
  localStorage.setItem("waffynx_force_mock", enabled ? "true" : "false");
}

export const wafApi = {
  // Authentication
  async login(username: string, password: string): Promise<UserSession> {
    if (isMockMode()) {
      return mockLogin(username, password);
    }
    try {
      const res = await apiFetch<{ token: string; role: string }>("/api/v1/auth/login", {
        method: "POST",
        body: JSON.stringify({ username, password }),
      });
      const session: UserSession = {
        token: res.token,
        username,
        role: (res.role as UserSession["role"]) || "admin",
        expires_at: Date.now() + 1000 * 60 * 60 * 8,
      };
      localStorage.setItem("waffynx_auth", JSON.stringify(session));
      return session;
    } catch (err) {
      // No mock fallback: an invented session with a fake token made the whole
      // dashboard look alive while every request behind it was failing 401.
      throw err;
    }
  },

  getCurrentSession(): UserSession | null {
    return getStoredSession();
  },

  logout(): void {
    clearSession();
  },

  // Telemetry & Status
  async getStatus(): Promise<Status> {
    if (isMockMode()) {
      return {
        ...mockStatus,
        banned_ips_count: mockBanned.length,
        plugins_active: mockPlugins.filter((p) => p.enabled).length,
      };
    }
    try {
      return await apiFetch<Status>("/api/v1/status");
    } catch {
      return mockStatus;
    }
  },

  async getMetrics(): Promise<Metrics> {
    if (isMockMode()) {
      return {
        ...MOCK_INITIAL_METRICS,
        go: {
          ...MOCK_INITIAL_METRICS.go,
          heap_alloc: Math.round(2.5 * 1024 * 1024 + Math.random() * 500000),
          goroutines: Math.round(6 + Math.random() * 4),
        },
      };
    }
    try {
      return await apiFetch<Metrics>("/api/v1/metrics");
    } catch {
      return MOCK_INITIAL_METRICS;
    }
  },

  // Security Policies
  async getRules(): Promise<Rule[]> {
    if (isMockMode()) {
      return mockRules;
    }
    try {
      return await apiFetch<Rule[]>("/api/v1/rules");
    } catch {
      return mockRules;
    }
  },

  // Sites: the reverse-proxy topology. No mock fallback on purpose: if the API
  // cannot list them, the operator must see the error, not an invented topology.
  async listSites(): Promise<Site[]> {
    // The API wraps the list: {"sites": [...]}. Verified against a running
    // container, not inferred from the handler name.
    const data = await apiFetch<{ sites: Site[] }>("/api/v1/sites");
    return data.sites ?? [];
  },

  async createSite(site: Site): Promise<Site> {
    return apiFetch<Site>("/api/v1/sites", {
      method: "POST",
      body: JSON.stringify(site),
    });
  },

  async updateSite(host: string, site: Site): Promise<Site> {
    return apiFetch<Site>(`/api/v1/sites/${encodeURIComponent(host)}`, {
      method: "PUT",
      body: JSON.stringify(site),
    });
  },

  async deleteSite(host: string): Promise<void> {
    await apiFetch(`/api/v1/sites/${encodeURIComponent(host)}`, { method: "DELETE" });
  },

  // Host Firewall
  async getBannedIPs(): Promise<BannedIP[]> {
    if (isMockMode()) {
      return mockBanned;
    }
    try {
      const data = await apiFetch<{ banned_ips: BannedIP[] }>("/api/v1/firewall/rules");
      return data.banned_ips || [];
    } catch {
      return mockBanned;
    }
  },

  async unbanIP(ip: string): Promise<void> {
    if (isMockMode()) {
      mockBanned = mockBanned.filter((b) => b.ip !== ip);
      return;
    }
    try {
      await apiFetch(`/api/v1/firewall/unblock/${encodeURIComponent(ip)}`, {
        method: "DELETE",
      });
    } catch {
      // In dev or mock fallback
      mockBanned = mockBanned.filter((b) => b.ip !== ip);
    }
  },

  // Marketplace
  async getPlugins(): Promise<PluginItem[]> {
    if (isMockMode()) {
      return mockPlugins;
    }
    try {
      const data = await apiFetch<{ plugins: PluginItem[] }>("/api/v1/marketplace");
      return data.plugins || mockPlugins;
    } catch {
      return mockPlugins;
    }
  },

  async togglePlugin(id: string, enabled: boolean): Promise<void> {
    mockPlugins = mockPlugins.map((p) => (p.id === id ? { ...p, enabled } : p));
    if (!isMockMode()) {
      try {
        await apiFetch(`/api/v1/marketplace/${encodeURIComponent(id)}/toggle`, {
          method: "POST",
          body: JSON.stringify({ enabled }),
        });
      } catch {
        // Optimistic UI state already applied
      }
    }
  },

  // Live Stream Subscription (SSE or Mock Stream)
  subscribeEvents(
    onEvent: (event: WafEvent) => void,
    onStatus: (connected: boolean) => void
  ): () => void {
    if (isMockMode()) {
      onStatus(true);
      // Seed initial pool
      const initial = getInitialEvents();
      initial.forEach(onEvent);
      // Start generator stream
      return startMockEventStream(onEvent, 2200);
    }

    const session = getStoredSession();

    // Authenticate the stream with a header. EventSource cannot send one, so the
    // previous implementation appended the JWT to the URL, which lands in the
    // nginx access log, in proxy logs and in browser history — and the API only
    // accepts Authorization, so the stream never authenticated in production
    // anyway.
    const controller = new AbortController();

    const connect = async () => {
      try {
        const res = await fetch("/api/v1/events", {
          headers: {
            Accept: "text/event-stream",
            ...(session?.token ? { Authorization: `Bearer ${session.token}` } : {}),
          },
          signal: controller.signal,
        });
        if (!res.ok || !res.body) {
          onStatus(false);
          return;
        }
        onStatus(true);

        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";

        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });

          // Server-Sent Events frames are separated by a blank line; only the
          // `data:` fields carry the payload.
          let boundary = buffer.indexOf("\n\n");
          while (boundary >= 0) {
            const frame = buffer.slice(0, boundary);
            buffer = buffer.slice(boundary + 2);
            boundary = buffer.indexOf("\n\n");

            const data = frame
              .split("\n")
              .filter((line) => line.startsWith("data:"))
              .map((line) => line.slice(5).trim())
              .join("\n");
            if (!data) continue;

            try {
              onEvent(JSON.parse(data) as WafEvent);
            } catch {
              // A frame that is not valid JSON is not worth tearing the stream
              // down for: the next one may be fine.
            }
          }
        }
        onStatus(false);
      } catch {
        // Aborting is the normal teardown path, not a connection failure.
        if (!controller.signal.aborted) onStatus(false);
      }
    };

    void connect();

    return () => controller.abort();
  },
};
