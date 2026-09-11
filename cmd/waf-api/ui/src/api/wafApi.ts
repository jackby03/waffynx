import { apiFetch } from "./client";
import type { Status, Metrics, Rule, BannedIP, PluginItem, WafEvent, UserSession } from "./types";
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
      // Fallback to mock login in case backend is down or during transition
      if (username === "admin" && password === "admin") {
        return mockLogin(username, password);
      }
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
    const sseUrl = `/api/v1/events${session?.token ? `?token=${encodeURIComponent(session.token)}` : ""}`;
    let es: EventSource | null = null;
    let fallbackCleanup: (() => void) | null = null;

    try {
      es = new EventSource(sseUrl);
      es.onopen = () => {
        onStatus(true);
      };
      es.onmessage = (msg) => {
        try {
          const parsed = JSON.parse(msg.data) as WafEvent;
          onEvent(parsed);
        } catch {
          // ignore parse error
        }
      };
      es.onerror = () => {
        onStatus(false);
        // Fallback to mock stream if real SSE fails in development
        if (import.meta.env.DEV && !fallbackCleanup) {
          fallbackCleanup = startMockEventStream(onEvent, 2500);
        }
      };
    } catch {
      onStatus(false);
      fallbackCleanup = startMockEventStream(onEvent, 2500);
    }

    return () => {
      if (es) es.close();
      if (fallbackCleanup) fallbackCleanup();
    };
  },
};
