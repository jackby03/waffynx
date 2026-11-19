import React, { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import type {
  AnalyticsSecurityEvent,
  AnalyticsSummary,
  BannedIP,
  ClusterTopology,
  Exclusion,
  FirewallStatus,
  LiveStatsFrame,
  ManagedRule,
  Metrics,
  PluginMetadata,
  Site,
  Status,
  SystemConfig,
  Verdict,
  WafEvent,
} from "../api/types";
import { wafApi } from "../api/wafApi";
import { useAuth } from "./AuthContext";
import { eventIdentity } from "../utils/format";

const MAX_EVENTS = 1000;
const MAX_STATS_SAMPLES = 40;

export interface WafContextType {
  events: WafEvent[];
  status: Status | null;
  metrics: Metrics | null;
  config: SystemConfig | null;
  rules: ManagedRule[];
  sites: Site[];
  firewall: FirewallStatus;
  bannedIPs: BannedIP[];
  plugins: PluginMetadata[];
  liveStats: LiveStatsFrame[];
  topology: ClusterTopology | null;
  exclusions: Exclusion[];
  analyticsSource: "clickhouse" | "broker";
  analyticsSummary: AnalyticsSummary | null;
  connected: boolean;
  paused: boolean;
  bufferedCount: number;
  loadingInitial: boolean;
  loadError: string | null;
  inspectedEvent: WafEvent | null;
  setInspectedEvent: (ev: WafEvent | null) => void;
  togglePaused: () => void;
  clearEvents: () => void;
  banIP: (ip: string, reason: string, ttlSeconds: number) => Promise<BannedIP>;
  unbanIP: (ip: string) => Promise<void>;
  createExclusion: (ex: Omit<Exclusion, "id" | "created_at">) => Promise<Exclusion>;
  deleteExclusion: (id: string) => Promise<void>;
  refreshSites: () => Promise<void>;
  refreshConfig: () => Promise<void>;
  refreshFirewall: () => Promise<void>;
  refreshExclusions: () => Promise<void>;
  refreshTopology: () => Promise<void>;
  refreshAll: () => Promise<void>;
}

const WafContext = createContext<WafContextType | undefined>(undefined);

function dedupeEvents(list: WafEvent[]): WafEvent[] {
  const seen = new Set<string>();
  const out: WafEvent[] = [];
  for (const ev of list) {
    const k = eventIdentity(ev);
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(ev);
    if (out.length >= MAX_EVENTS) break;
  }
  return out;
}

function mapAnalyticsAction(action: string): Verdict {
  switch (action) {
    case "allow":
      return "allow";
    case "rate_limited":
      return "rate_limited";
    case "challenge":
      return "challenge";
    default:
      return "deny";
  }
}

function projectAnalyticsEvent(ev: AnalyticsSecurityEvent): WafEvent {
  return {
    type: ev.action,
    timestamp: ev.timestamp,
    method: ev.method || "GET",
    path: ev.path || "/",
    remote_ip: ev.remote_ip || "",
    rule_id: ev.rule_id || ev.stage || "waf",
    reason: ev.reason || (ev.shadow_mode ? "Shadow match" : ""),
    payload: ev.body_snippet || ev.path,
    action: mapAnalyticsAction(ev.action),
    matched_field: ev.stage || "request",
    matched_value: ev.body_snippet || ev.path || "",
  };
}

export const WafProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated, logout } = useAuth();

  const [events, setEvents] = useState<WafEvent[]>([]);
  const [status, setStatus] = useState<Status | null>(null);
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [config, setConfig] = useState<SystemConfig | null>(null);
  const [rules, setRules] = useState<ManagedRule[]>([]);
  const [sites, setSites] = useState<Site[]>([]);
  const [firewall, setFirewall] = useState<FirewallStatus>({
    enabled: false,
    backend: "nftables",
    rules: [],
  });
  const [plugins, setPlugins] = useState<PluginMetadata[]>([]);
  const [liveStats, setLiveStats] = useState<LiveStatsFrame[]>([]);
  const [topology, setTopology] = useState<ClusterTopology | null>(null);
  const [exclusions, setExclusions] = useState<Exclusion[]>([]);
  const [analyticsSource, setAnalyticsSource] = useState<"clickhouse" | "broker">("broker");
  const [analyticsSummary, setAnalyticsSummary] = useState<AnalyticsSummary | null>(null);
  const [connected, setConnected] = useState(false);
  const [paused, setPaused] = useState(false);
  const [bufferedCount, setBufferedCount] = useState(0);
  const [loadingInitial, setLoadingInitial] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [inspectedEvent, setInspectedEvent] = useState<WafEvent | null>(null);

  const eventsRef = useRef<WafEvent[]>([]);
  const seenRef = useRef<Set<string>>(new Set());
  const pausedRef = useRef(false);
  const bufferedRef = useRef<WafEvent[]>([]);

  const commitEvents = useCallback((next: WafEvent[]) => {
    eventsRef.current = next;
    seenRef.current = new Set(next.map(eventIdentity));
    setEvents(next);
  }, []);

  const ingestLive = useCallback(
    (ev: WafEvent) => {
      if (pausedRef.current) {
        bufferedRef.current = [ev, ...bufferedRef.current.slice(0, MAX_EVENTS - 1)];
        setBufferedCount(bufferedRef.current.length);
        return;
      }
      const key = eventIdentity(ev);
      if (seenRef.current.has(key)) return;
      const next = [ev, ...eventsRef.current].slice(0, MAX_EVENTS);
      commitEvents(next);
    },
    [commitEvents]
  );

  const refreshSites = useCallback(async () => {
    const list = await wafApi.listSites();
    setSites(list);
  }, []);

  const refreshConfig = useCallback(async () => {
    const cfg = await wafApi.getConfig();
    setConfig(cfg);
  }, []);

  const refreshFirewall = useCallback(async () => {
    const fw = await wafApi.getFirewallStatus();
    setFirewall(fw);
  }, []);

  const refreshExclusions = useCallback(async () => {
    const list = await wafApi.listExclusions();
    setExclusions(list);
  }, []);

  const refreshTopology = useCallback(async () => {
    const topo = await wafApi.getClusterTopology();
    setTopology(topo);
  }, []);

  const refreshAll = useCallback(async () => {
    setLoadingInitial(true);
    try {
      const results = await Promise.allSettled([
        wafApi.getStatus(),
        wafApi.getMetrics(),
        wafApi.getRules(),
        wafApi.listSites(),
        wafApi.getFirewallStatus(),
        wafApi.getPlugins(),
        wafApi.getConfig(),
        wafApi.getEventHistory(1000),
        wafApi.getClusterTopology(),
        wafApi.listExclusions(),
        wafApi.getAnalyticsEvents({ limit: 500 }),
        wafApi.getAnalyticsSummary(24),
      ]);

      const [stR, mtR, rlR, siR, fwR, plR, cfgR, histR, topoR, exR, anEvR, anSumR] = results;
      let firstErr: string | null = null;

      if (stR.status === "fulfilled") setStatus(stR.value);
      else firstErr = stR.reason instanceof Error ? stR.reason.message : "Failed to load status";

      if (mtR.status === "fulfilled") setMetrics(mtR.value);
      if (rlR.status === "fulfilled") setRules(rlR.value);
      if (siR.status === "fulfilled") setSites(siR.value);
      if (fwR.status === "fulfilled") setFirewall(fwR.value);
      if (plR.status === "fulfilled") setPlugins(plR.value);
      if (cfgR.status === "fulfilled") setConfig(cfgR.value);
      if (topoR.status === "fulfilled") setTopology(topoR.value);
      if (exR.status === "fulfilled") setExclusions(exR.value);

      const mergedEvents: WafEvent[] = [...eventsRef.current];
      if (anEvR.status === "fulfilled") {
        setAnalyticsSource(anEvR.value.source);
        if (anEvR.value.source === "clickhouse" && anEvR.value.events.length > 0) {
          for (const raw of anEvR.value.events) {
            if (raw.action !== "allow") {
              mergedEvents.push(projectAnalyticsEvent(raw));
            }
          }
        }
      }
      if (histR.status === "fulfilled") {
        mergedEvents.push(...histR.value);
      }
      if (mergedEvents.length > 0) {
        mergedEvents.sort((a, b) => (b.timestamp || "").localeCompare(a.timestamp || ""));
        commitEvents(dedupeEvents(mergedEvents));
      }

      if (anSumR.status === "fulfilled") {
        setAnalyticsSummary(anSumR.value.summary);
      }

      const allFailed = results.every((r) => r.status === "rejected");
      setLoadError(allFailed ? (firstErr ?? "Could not reach the control plane") : null);
    } catch (err) {
      setLoadError(err instanceof Error ? err.message : "Could not reach the control plane");
    } finally {
      setLoadingInitial(false);
    }
  }, [commitEvents]);

  useEffect(() => {
    if (!isAuthenticated) {
      commitEvents([]);
      setLiveStats([]);
      setTopology(null);
      setExclusions([]);
      setAnalyticsSummary(null);
      setConnected(false);
      setInspectedEvent(null);
      return;
    }

    void refreshAll();
    const timer = setInterval(() => {
      wafApi.getMetrics().then(setMetrics).catch(() => {});
      wafApi.getStatus().then(setStatus).catch(() => {});
      wafApi.getClusterTopology().then(setTopology).catch(() => {});
      wafApi
        .getAnalyticsEvents({ limit: 200 })
        .then((res) => {
          setAnalyticsSource(res.source);
          if (res.source === "clickhouse" && res.events.length > 0) {
            const projected = res.events
              .filter((e) => e.action !== "allow")
              .map(projectAnalyticsEvent);
            if (projected.length > 0) {
              const combined = dedupeEvents([...projected, ...eventsRef.current]);
              combined.sort((a, b) => (b.timestamp || "").localeCompare(a.timestamp || ""));
              commitEvents(combined);
            }
          }
        })
        .catch(() => {});
    }, 8000);
    return () => clearInterval(timer);
  }, [isAuthenticated, refreshAll, commitEvents]);

  // Single unified SSE stream across the entire console.
  useEffect(() => {
    if (!isAuthenticated) return;
    const unsub = wafApi.subscribeEvents(
      ingestLive,
      setConnected,
      (stats) => {
        setLiveStats((prev) => [...prev.slice(-(MAX_STATS_SAMPLES - 1)), stats]);
      },
      () => {
        setConnected(false);
        logout();
      }
    );
    return unsub;
  }, [isAuthenticated, ingestLive, logout]);

  const togglePaused = useCallback(() => {
    const nextPaused = !pausedRef.current;
    pausedRef.current = nextPaused;
    setPaused(nextPaused);
    if (!nextPaused && bufferedRef.current.length > 0) {
      const merged = dedupeEvents([...bufferedRef.current, ...eventsRef.current]);
      bufferedRef.current = [];
      setBufferedCount(0);
      commitEvents(merged);
    }
  }, [commitEvents]);

  const clearEvents = useCallback(() => {
    bufferedRef.current = [];
    setBufferedCount(0);
    commitEvents([]);
  }, [commitEvents]);

  const banIP = useCallback(
    async (ip: string, reason: string, ttlSeconds: number) => {
      const created = await wafApi.banIP(ip, reason, ttlSeconds);
      await refreshFirewall();
      return created;
    },
    [refreshFirewall]
  );

  const unbanIP = useCallback(async (ip: string) => {
    await wafApi.unbanIP(ip);
    setFirewall((prev) => ({
      ...prev,
      rules: prev.rules.filter((b) => b.ip !== ip),
    }));
  }, []);

  const createExclusion = useCallback(
    async (ex: Omit<Exclusion, "id" | "created_at">) => {
      const created = await wafApi.createExclusion(ex);
      await refreshExclusions();
      return created;
    },
    [refreshExclusions]
  );

  const deleteExclusion = useCallback(async (id: string) => {
    await wafApi.deleteExclusion(id);
    setExclusions((prev) => prev.filter((e) => e.id !== id));
  }, []);

  return (
    <WafContext.Provider
      value={{
        events,
        status,
        metrics,
        config,
        rules,
        sites,
        firewall,
        bannedIPs: firewall.rules,
        plugins,
        liveStats,
        topology,
        exclusions,
        analyticsSource,
        analyticsSummary,
        connected,
        paused,
        bufferedCount,
        loadingInitial,
        loadError,
        inspectedEvent,
        setInspectedEvent,
        togglePaused,
        clearEvents,
        banIP,
        unbanIP,
        createExclusion,
        deleteExclusion,
        refreshSites,
        refreshConfig,
        refreshFirewall,
        refreshExclusions,
        refreshTopology,
        refreshAll,
      }}
    >
      {children}
    </WafContext.Provider>
  );
};

export function useWaf(): WafContextType {
  const ctx = useContext(WafContext);
  if (!ctx) throw new Error("useWaf must be used within a WafProvider");
  return ctx;
}
