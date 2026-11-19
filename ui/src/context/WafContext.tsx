import React, { createContext, useContext, useState, useEffect, useCallback } from "react";
import type { WafEvent, Status, Metrics, Rule, BannedIP, PluginItem } from "../api/types";
import { wafApi } from "../api/wafApi";
import { useAuth } from "./AuthContext";

interface WafContextType {
  events: WafEvent[];
  status: Status | null;
  metrics: Metrics | null;
  rules: Rule[];
  bannedIPs: BannedIP[];
  plugins: PluginItem[];
  connected: boolean;
  /** Set when the last refresh failed. Views must show it instead of looking empty. */
  loadError: string | null;
  unbanIP: (ip: string) => Promise<void>;
  refreshAll: () => Promise<void>;
}

const WafContext = createContext<WafContextType | undefined>(undefined);

export const WafProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated } = useAuth();
  const [events, setEvents] = useState<WafEvent[]>([]);
  const [status, setStatus] = useState<Status | null>(null);
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [rules, setRules] = useState<Rule[]>([]);
  const [bannedIPs, setBannedIPs] = useState<BannedIP[]>([]);
  const [plugins, setPlugins] = useState<PluginItem[]>([]);
  const [connected, setConnected] = useState<boolean>(false);
  const [loadError, setLoadError] = useState<string | null>(null);

  const refreshAll = useCallback(async () => {
    try {
      const [st, mt, rl, bp, pl] = await Promise.all([
        wafApi.getStatus(),
        wafApi.getMetrics(),
        wafApi.getRules(),
        wafApi.getBannedIPs(),
        wafApi.getPlugins(),
      ]);
      setStatus(st);
      setMetrics(mt);
      setRules(rl);
      setBannedIPs(bp);
      setPlugins(pl);
      setLoadError(null);
    } catch (err) {
      // Surface it: an empty dashboard and a broken dashboard looked identical.
      setLoadError(err instanceof Error ? err.message : "Could not reach the control plane");
    }
  }, []);

  // Poll metrics every 5 seconds
  useEffect(() => {
    if (!isAuthenticated) return;
    refreshAll();
    const timer = setInterval(() => {
      wafApi.getMetrics().then(setMetrics).catch(() => {});
      wafApi.getStatus().then(setStatus).catch(() => {});
    }, 5000);
    return () => clearInterval(timer);
  }, [isAuthenticated, refreshAll]);

  // Subscribe to live events
  useEffect(() => {
    if (!isAuthenticated) return;
    const unsub = wafApi.subscribeEvents(
      (ev) => {
        setEvents((prev) => [ev, ...prev.slice(0, 199)]); // Keep last 200 events
      },
      (conn) => {
        setConnected(conn);
      }
    );
    return unsub;
  }, [isAuthenticated]);

  const unbanIP = async (ip: string) => {
    await wafApi.unbanIP(ip);
    setBannedIPs((prev) => prev.filter((b) => b.ip !== ip));
  };

  return (
    <WafContext.Provider
      value={{
        events,
        status,
        metrics,
        rules,
        bannedIPs,
        plugins,
        connected,
        loadError,
        unbanIP,

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
