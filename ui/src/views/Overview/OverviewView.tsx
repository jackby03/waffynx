import React, { useMemo, useState } from "react";
import {
  ArrowRight,
  Ban,
  CheckCircle2,
  Shield,
  ShieldAlert,
  Terminal,
  TriangleAlert,
} from "lucide-react";
import { useWaf } from "../../context/WafContext";
import { useToast } from "../../context/ToastContext";
import { KpiCard } from "../../components/common/KpiCard";
import { Badge } from "../../components/common/Badge";
import { EmptyState } from "../../components/common/EmptyState";
import { CodeBlock } from "../../components/common/CodeBlock";
import { Sparkline } from "../../components/charts/Sparkline";
import { TimeSeriesChart } from "../../components/charts/TimeSeriesChart";
import { ProportionBarList } from "../../components/charts/ProportionBarList";
import {
  buildMinuteBuckets,
  classifyEventVector,
  formatTime,
  VECTOR_LABELS,
} from "../../utils/format";
import { ApiError } from "../../api/client";
import type { ViewId } from "../../router/routes";

interface OverviewViewProps {
  onNavigate: (view: ViewId, presetQuery?: string) => void;
}

function topBy<T>(items: T[], keyFn: (item: T) => string, limit: number): { key: string; count: number }[] {
  const counts = new Map<string, number>();
  for (const item of items) {
    const k = keyFn(item);
    if (!k) continue;
    counts.set(k, (counts.get(k) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
}

export const OverviewView: React.FC<OverviewViewProps> = ({ onNavigate }) => {
  const {
    events,
    status,
    metrics,
    config,
    rules,
    sites,
    bannedIPs,
    liveStats,
    loadingInitial,
    loadError,
    setInspectedEvent,
    banIP,
  } = useWaf();
  const { pushToast } = useToast();

  const [windowMinutes, setWindowMinutes] = useState<15 | 30 | 60>(30);
  const [banningIp, setBanningIp] = useState<string | null>(null);

  const now = Date.now();
  const buckets = useMemo(() => buildMinuteBuckets(events, windowMinutes, now), [events, windowMinutes, now]);
  const windowStart = now - windowMinutes * 60_000;

  const inWindow = useMemo(
    () =>
      events.filter((e) => {
        const ts = Date.parse(e.timestamp);
        return !Number.isNaN(ts) && ts >= windowStart;
      }),
    [events, windowStart]
  );

  const distinctIPs = useMemo(() => new Set(events.map((e) => e.remote_ip).filter(Boolean)).size, [events]);
  const topRules = useMemo(() => topBy(events, (e) => e.rule_id, 6), [events]);
  const topIPs = useMemo(() => topBy(events, (e) => e.remote_ip, 6), [events]);
  const topVectors = useMemo(() => topBy(events, (e) => classifyEventVector(e), 5), [events]);

  const bannedSet = useMemo(() => new Set(bannedIPs.map((b) => b.ip)), [bannedIPs]);
  const tlsSites = useMemo(() => sites.filter((s) => Boolean(s.tls)).length, [sites]);
  const criticalRules = useMemo(() => rules.filter((r) => r.severity === "critical").length, [rules]);

  const heapMB = metrics ? Math.round(metrics.go.heap_alloc / 1024 / 1024) : null;
  const goroutines = metrics?.go.goroutines ?? status?.goroutines ?? null;
  const heapSeries = useMemo(
    () => liveStats.map((s) => s.heap_mb).filter((v): v is number => typeof v === "number"),
    [liveStats]
  );

  const sidecarFailOpen = Boolean(config?.sidecar?.fail_open ?? config?.sidecar?.FailOpen);
  const learningMode = Boolean(config?.appsec?.learning_mode);
  const engine = status?.config?.engine ?? config?.appsec?.engine ?? "basic-go";
  const firstSiteHost = sites[0]?.host || "app.example.test";

  const quickBan = async (ip: string) => {
    setBanningIp(ip);
    try {
      await banIP(ip, "Quick 1h ban from Overview", 3600);
      pushToast("ok", `Banned ${ip}`, "Active at WAF sidecar layer for 1 hour.");
    } catch (err) {
      pushToast("error", `Failed to ban ${ip}`, err instanceof ApiError ? err.message : "Request rejected");
    } finally {
      setBanningIp(null);
    }
  };

  const recent = events.slice(0, 10);

  return (
    <div className="canvas-inner">
      <header className="view-header">
        <div>
          <h1 className="view-title" id="view-heading" tabIndex={-1}>
            Security Overview
          </h1>
          <p className="view-subtitle">
            Live posture and blocked-request telemetry reported by the control plane. Every metric is
            computed directly from the stored ring (max 1,000 events) and live SSE feed.
          </p>
        </div>
        <div className="view-actions">
          <button type="button" className="btn" onClick={() => onNavigate("sites")}>
            Manage Sites
          </button>
          <button type="button" className="btn btn-primary" onClick={() => onNavigate("events")}>
            Open Live Forensics
            <ArrowRight size={14} aria-hidden="true" />
          </button>
        </div>
      </header>

      {loadError && (
        <div className="alert-banner error" role="alert">
          <span className="alert-banner-content">
            <TriangleAlert size={16} aria-hidden="true" />
            <span>{loadError}</span>
          </span>
        </div>
      )}

      {/* Global Security Posture Strip */}
      <section className="posture-strip" aria-label="Security posture summary">
        <div className="posture-items">
          <div className="posture-item">
            {sidecarFailOpen ? (
              <Badge variant="critical" dot>
                FAIL-OPEN WARNING
              </Badge>
            ) : (
              <Badge variant="ok" dot>
                FAIL-CLOSED ENFORCED
              </Badge>
            )}
          </div>
          <div className="posture-item">
            <span className="text-muted">Scorer:</span>
            <strong className="mono">{engine}</strong>
          </div>
          <div className="posture-item">
            <span className="text-muted">Mode:</span>
            <Badge variant={learningMode ? "ml" : "info"}>
              {learningMode ? "Learning + Inspect" : "Active Prevention"}
            </Badge>
          </div>
          <div className="posture-item">
            <span className="text-muted">Build:</span>
            <span className="mono">{status?.version ?? "—"}</span>
            {status?.git_commit && (
              <span className="mono text-muted">({status.git_commit})</span>
            )}
          </div>
        </div>
        <button type="button" className="btn btn-sm btn-ghost" onClick={() => onNavigate("system")}>
          System &amp; Config
          <ArrowRight size={13} aria-hidden="true" />
        </button>
      </section>

      {/* 5-Card Bento KPI Strip */}
      <section className="kpi-grid" aria-label="Key telemetry indicators">
        <KpiCard
          title={`Blocked (${windowMinutes}m)`}
          value={loadingInitial && events.length === 0 ? "…" : inWindow.length}
          subtext={`${events.length} stored in ring · ${distinctIPs} distinct IPs`}
          badge="Enforced"
          tone="critical"
          sparkline={<Sparkline values={buckets.map((b) => b.count)} color="var(--status-critical)" />}
        />
        <KpiCard
          title="Protected Sites"
          value={sites.length}
          subtext={`${tlsSites} HTTPS/TLS · ${sites.length - tlsSites} plain HTTP`}
          badge="Reverse Proxy"
          tone="info"
        />
        <KpiCard
          title="Managed Signatures"
          value={rules.length}
          subtext={`${criticalRules} critical · Aho-Corasick single pass`}
          badge="Catalog"
          tone="ok"
        />
        <KpiCard
          title="Active IP Bans"
          value={bannedIPs.length}
          subtext="Evaluated in sidecar before plugin chain"
          badge="WAF Layer"
          tone={bannedIPs.length > 0 ? "high" : "default"}
        />
        <KpiCard
          title="API Runtime"
          value={heapMB === null ? "—" : `${heapMB} MB`}
          subtext={goroutines === null ? "Go runtime" : `${goroutines} goroutines active`}
          badge={status?.go_version ?? "Go"}
          tone="ml"
          sparkline={heapSeries.length >= 2 ? <Sparkline values={heapSeries} color="var(--status-ml)" /> : undefined}
        />
      </section>

      {/* Main Timeline Chart */}
      <section className="panel">
        <div className="panel-header">
          <div>
            <h2 className="panel-title">Blocked Requests Timeline</h2>
            <p className="panel-subtitle">
              Real per-minute block counts. The data plane only emits blocked/rate-limited verdicts,
              so no synthetic allowed baseline is plotted.
            </p>
          </div>
          <div className="pill-group" role="group" aria-label="Time window">
            {([15, 30, 60] as const).map((mins) => (
              <button
                key={mins}
                type="button"
                className="pill"
                aria-pressed={windowMinutes === mins}
                onClick={() => setWindowMinutes(mins)}
              >
                {mins}m
              </button>
            ))}
          </div>
        </div>
        <div className="panel-body">
          {events.length === 0 && !loadingInitial ? (
            <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
              <EmptyState
                icon={<Shield size={22} />}
                title="No blocked traffic recorded yet"
                description="Waffynx is listening and waiting for inspected traffic. Send a safe request and an attack probe below to verify live enforcement."
              />
              <div className="split-2">
                <CodeBlock
                  label="1. Benign probe (expect 200 OK)"
                  copyText={`curl -i -H 'Host: ${firstSiteHost}' 'http://localhost:8080/'`}
                >
                  {`curl -i -H 'Host: ${firstSiteHost}' 'http://localhost:8080/'`}
                </CodeBlock>
                <CodeBlock
                  label="2. SQLi attack probe (expect 403 Forbidden)"
                  copyText={`curl -i -H 'Host: ${firstSiteHost}' 'http://localhost:8080/?q=UNION+SELECT+1,2,3'`}
                >
                  {`curl -i -H 'Host: ${firstSiteHost}' 'http://localhost:8080/?q=UNION+SELECT+1,2,3'`}
                </CodeBlock>
              </div>
            </div>
          ) : (
            <TimeSeriesChart
              buckets={buckets}
              caption={`Blocked requests per minute (last ${windowMinutes} minutes)`}
            />
          )}
        </div>
      </section>

      {/* Breakdown Split: Top Rules, Top Sources (with 1-click Ban), Top Vectors */}
      <div className="split-2">
        <section className="panel">
          <div className="panel-header">
            <div>
              <h2 className="panel-title">Top Triggered Rules</h2>
              <p className="panel-subtitle">Click a rule ID to filter matching incidents</p>
            </div>
            <Badge variant="neutral">{topRules.length} rules</Badge>
          </div>
          <div className="panel-body">
            {topRules.length === 0 ? (
              <EmptyState
                icon={<CheckCircle2 size={20} />}
                title="No signatures triggered"
                description="Triggered catalog rules, custom policies, and bans appear here."
              />
            ) : (
              <ProportionBarList
                items={topRules.map((r) => ({ key: r.key, label: r.key, count: r.count }))}
                total={events.length}
                tone="critical"
                onSelect={(item) => onNavigate("events", item.key)}
              />
            )}
          </div>
        </section>

        <section className="panel">
          <div className="panel-header">
            <div>
              <h2 className="panel-title">Top Offending Source IPs</h2>
              <p className="panel-subtitle">One-click WAF-layer mitigation directly from telemetry</p>
            </div>
            <Badge variant="neutral">{distinctIPs} unique</Badge>
          </div>
          <div className="panel-body">
            {topIPs.length === 0 ? (
              <EmptyState
                icon={<ShieldAlert size={20} />}
                title="No offending sources"
                description="Source IPs blocked by the engine will be ranked here."
              />
            ) : (
              <ProportionBarList
                items={topIPs.map((ip) => ({ key: ip.key, label: ip.key, count: ip.count }))}
                total={events.length}
                tone="high"
                onSelect={(item) => onNavigate("events", item.key)}
                renderAction={(item) =>
                  bannedSet.has(item.key) ? (
                    <Badge variant="critical">Banned</Badge>
                  ) : (
                    <button
                      type="button"
                      className="btn btn-danger btn-sm"
                      disabled={banningIp === item.key}
                      onClick={() => void quickBan(item.key)}
                      aria-label={`Ban ${item.key} for 1 hour`}
                    >
                      <Ban size={12} aria-hidden="true" />
                      <span>{banningIp === item.key ? "…" : "Ban 1h"}</span>
                    </button>
                  )
                }
              />
            )}
          </div>
        </section>
      </div>

      {/* Vector Distribution + Recent Blocks */}
      <div className="split-2">
        <section className="panel">
          <div className="panel-header">
            <div>
              <h2 className="panel-title">Attack Vector Distribution</h2>
              <p className="panel-subtitle">Derived from triggered rule categories in the stored ring</p>
            </div>
          </div>
          <div className="panel-body">
            {topVectors.length === 0 ? (
              <EmptyState
                icon={<Terminal size={20} />}
                title="No attack vectors yet"
                description="SQLi, XSS, LFI, RCE, scanners, and rate-limit spikes break down here."
              />
            ) : (
              <ProportionBarList
                items={topVectors.map((v) => ({
                  key: v.key,
                  label: VECTOR_LABELS[v.key as keyof typeof VECTOR_LABELS] ?? v.key,
                  count: v.count,
                }))}
                total={events.length}
                tone="ml"
              />
            )}
          </div>
        </section>

        <section className="panel">
          <div className="panel-header">
            <div>
              <h2 className="panel-title">Latest Mitigated Requests</h2>
              <p className="panel-subtitle">Select any row to open deep forensic inspection</p>
            </div>
            <button type="button" className="btn btn-sm" onClick={() => onNavigate("events")}>
              View all ({events.length})
            </button>
          </div>
          {recent.length === 0 ? (
            <EmptyState
              icon={<Shield size={20} />}
              title="Awaiting first security event"
              description="Live SSE verdicts appear here automatically."
            />
          ) : (
            <div className="table-scroll" role="region" aria-label="Latest mitigated requests" tabIndex={0}>
              <table className="data-table">
                <caption className="visually-hidden">Latest blocked requests</caption>
                <thead>
                  <tr>
                    <th scope="col">Time</th>
                    <th scope="col">Rule</th>
                    <th scope="col">Source IP</th>
                    <th scope="col">Target URI</th>
                  </tr>
                </thead>
                <tbody>
                  {recent.map((ev, idx) => (
                    <tr
                      key={`${ev.timestamp}-${ev.rule_id}-${idx}`}
                      className="row-clickable"
                      onClick={() => setInspectedEvent(ev)}
                    >
                      <td className="mono text-muted">
                        <button
                          type="button"
                          className="btn-link mono"
                          onClick={(e) => {
                            e.stopPropagation();
                            setInspectedEvent(ev);
                          }}
                        >
                          {formatTime(ev.timestamp)}
                        </button>
                      </td>
                      <td>
                        <span className="rule-chip">{ev.rule_id || "—"}</span>
                      </td>
                      <td className="mono">{ev.remote_ip || "—"}</td>
                      <td className="mono cell-truncate" title={ev.path}>
                        {ev.path || "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>
    </div>
  );
};
