import { apiFetch } from "./client";
import { toWafEvent } from "./events";
import { getStoredSession, storeSession, clearStoredSession } from "./session";
import type {
  Status,
  Metrics,
  Rule,
  BannedIP,
  PluginItem,
  WafEvent,
  UserSession,
  Site,
} from "./types";

/**
 * The only data source the dashboard has: the control-plane API.
 *
 * There is no mock mode and no "fall back to sample data" branch. Every one of
 * those branches made the UI look alive while it was disconnected — a rule matrix
 * that was not the catalog, bans that were not banned — and they hid the exact
 * failures they should surface.
 */
export const wafApi = {
  async login(username: string, password: string): Promise<UserSession> {
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
    storeSession(session);
    return session;
  },

  getCurrentSession(): UserSession | null {
    return getStoredSession();
  },

  logout(): void {
    clearStoredSession();
  },

  async getStatus(): Promise<Status> {
    return apiFetch<Status>("/api/v1/status");
  },

  async getMetrics(): Promise<Metrics> {
    return apiFetch<Metrics>("/api/v1/metrics");
  },

  async getRules(): Promise<Rule[]> {
    const data = await apiFetch<{ rules: Rule[] }>("/api/v1/rules");
    return data.rules ?? [];
  },

  // Sites: the reverse-proxy topology.
  async listSites(): Promise<Site[]> {
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

  // Bans are enforced at the WAF layer; the payload keys the list as "rules".
  async getBannedIPs(): Promise<BannedIP[]> {
    const data = await apiFetch<{ rules: BannedIP[] }>("/api/v1/firewall/rules");
    return data.rules ?? [];
  },

  async banIP(ip: string, reason?: string): Promise<void> {
    await apiFetch("/api/v1/firewall/block", {
      method: "POST",
      body: JSON.stringify({ ip, reason: reason ?? "Manual ban from Control Room" }),
    });
  },

  async unbanIP(ip: string): Promise<void> {
    await apiFetch(`/api/v1/firewall/unblock/${encodeURIComponent(ip)}`, { method: "DELETE" });
  },

  async getPlugins(): Promise<PluginItem[]> {
    const data = await apiFetch<PluginItem[] | { plugins: PluginItem[] }>("/api/v1/plugins");
    return Array.isArray(data) ? data : (data.plugins ?? []);
  },

  async togglePlugin(id: string, enabled: boolean): Promise<void> {
    await apiFetch(`/api/v1/plugins/${encodeURIComponent(id)}`, {
      method: "POST",
      body: JSON.stringify({ enabled }),
    });
  },

  /**
   * subscribeEvents streams the security event feed over SSE.
   *
   * It uses fetch plus a ReadableStream because EventSource cannot send an
   * Authorization header, and putting the token in the URL would write it to the
   * access log.
   */
  subscribeEvents(
    onEvent: (event: WafEvent) => void,
    onStatus: (connected: boolean) => void
  ): () => void {
    const session = getStoredSession();
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
              const ev = toWafEvent(JSON.parse(data));
              if (ev) onEvent(ev);
            } catch {
              // A frame that is not valid JSON is not worth tearing the stream down.
            }
          }
        }
        onStatus(false);
      } catch {
        if (!controller.signal.aborted) onStatus(false);
      }
    };

    void connect();
    return () => controller.abort();
  },
};
