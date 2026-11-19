import React, { useEffect, useMemo, useState } from "react";
import { KpiCard } from "../../components/common/KpiCard";
import { EmptyState } from "../../components/common/EmptyState";
import { IconShield } from "../../components/common/Icons";
import { ApiError } from "../../api/client";
import { wafApi } from "../../api/wafApi";
import type { WafEvent } from "../../api/types";

/**
 * Overview renders only what the control plane stores.
 *
 * The previous landing view drew a 30-minute chart and a distribution donut from
 * Math.random() and labelled the scorer "C++ Bridge / open-appsec" after that
 * engine had been removed. A dashboard that invents telemetry cannot be trusted
 * during an incident, so every number here is derived from
 * GET /api/v1/events/history or GET /api/v1/status.
 *
 * Two facts shape the layout and are stated on screen rather than hidden:
 *   - The API keeps a bounded ring (1000 events, since it started), not an archive.
 *   - The engine publishes only blocks; there is no "allowed" series to compare
 *     against, so no legit-vs-blocked chart is drawn.
 */

const WINDOW_MINUTES = 30;

interface Bucket {
  minute: number;
  label: string;
  count: number;
}

function buildBuckets(events: WafEvent[], now: number): Bucket[] {
  const buckets: Bucket[] = [];
  const start = Math.floor(now / 60000) * 60000 - (WINDOW_MINUTES - 1) * 60000;

  for (let i = 0; i < WINDOW_MINUTES; i += 1) {
    const minute = start + i * 60000;
    const date = new Date(minute);
    buckets.push({
      minute,
      label: `${String(date.getHours()).padStart(2, "0")}:${String(date.getMinutes()).padStart(2, "0")}`,
      count: 0,
    });
  }

  const index = new Map(buckets.map((b, i) => [b.minute, i]));
  for (const event of events) {
    const ts = Date.parse(event.timestamp);
    if (Number.isNaN(ts)) continue;
    const minute = Math.floor(ts / 60000) * 60000;
    const at = index.get(minute);
    if (at !== undefined) buckets[at].count += 1;
  }

  return buckets;
}

function topBy<T>(items: T[], key: (item: T) => string, limit: number): { key: string; count: number }[] {
  const counts = new Map<string, number>();
  for (const item of items) {
    const k = key(item);
    if (k === "") continue;
    counts.set(k, (counts.get(k) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([k, count]) => ({ key: k, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
}

const timeOf = (iso: string): string => {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "--:--:--" : d.toLocaleTimeString();
};

export const OverviewView: React.FC = () => {
  const [events, setEvents] = useState<WafEvent[]>([]);
  const [engine, setEngine] = useState<string>("unknown");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    const load = async () => {
      setLoading(true);
      setError(null);
      try {
        const [history, status] = await Promise.all([wafApi.getEventHistory(1000), wafApi.getStatus()]);
        if (cancelled) return;
        setEvents(history);
        setEngine(status.config?.engine ?? "unknown");
      } catch (err) {
        if (cancelled) return;
        setError(err instanceof ApiError ? err.message : "Could not load the event history");
      } finally {
        if (!cancelled) setLoading(false);
      }
    };

    void load();
    return () => {
      cancelled = true;
    };
  }, []);

  const now = Date.now();
  const buckets = useMemo(() => buildBuckets(events, now), [events, now]);
  const windowStart = now - WINDOW_MINUTES * 60000;
  const inWindow = useMemo(
    () => events.filter((e) => {
      const ts = Date.parse(e.timestamp);
      return !Number.isNaN(ts) && ts >= windowStart;
    }),
    [events, windowStart]
  );

  const peak = Math.max(1, ...buckets.map((b) => b.count));
  const distinctIPs = useMemo(() => new Set(events.map((e) => e.remote_ip)).size, [events]);
  const topRules = useMemo(() => topBy(events, (e) => e.rule_id, 5), [events]);
  const topIPs = useMemo(() => topBy(events, (e) => e.remote_ip, 5), [events]);
  const recent = events.slice(0, 8);

  return (
    <div className="view-stack">
      {error && (
        <div className="alert alert-error" role="alert">
          {error}
        </div>
      )}

      <section className="kpi-grid">
        <KpiCard
          title={`Blocked (${WINDOW_MINUTES}m)`}
          value={loading ? "…" : inWindow.length}
          subtext="Every event the engine publishes is a block"
          badge="Live enforcement"
          variant="critical"
        />
        <KpiCard
          title="Stored events"
          value={loading ? "…" : events.length}
          subtext="Bounded ring: the last 1000 since the API started"
          badge="Since start"
          variant="info"
        />
        <KpiCard
          title="Distinct sources"
          value={loading ? "…" : distinctIPs}
          subtext="Client addresses seen in the stored history"
          badge="Attack surface"
          variant="warning"
        />
        <KpiCard
          title="Engine"
          value={engine}
          subtext="In-process inspector; no external engine attached"
          badge="Configured"
          variant="success"
        />
      </section>

      <section className="panel">
        <div className="table-card-header">
          <div>
            <h2 className="table-title">Blocks per minute</h2>
            <p className="view-subtitle">
              Counts of stored events per minute. No "allowed" series is drawn: the engine does not
              publish allowed requests, so there is nothing to compare against.
            </p>
          </div>
        </div>
        {inWindow.length === 0 && !loading ? (
          <EmptyState
            title="No blocks in the last 30 minutes"
            description="The stored history has older events in the table below; this chart only covers the live window."
          />
        ) : (
        <div
          className="overview-bars"
          role="img"
          aria-label={`Blocks per minute over the last ${WINDOW_MINUTES} minutes, peak ${peak}`}
        >
          {buckets.map((bucket) => (
            <div
              key={bucket.minute}
              className="overview-bar"
              title={`${bucket.label} — ${bucket.count} block${bucket.count === 1 ? "" : "s"}`}
            >
              {bucket.count > 0 && (
                <span
                  className="overview-bar-fill"
                  style={{ height: `${(bucket.count / peak) * 100}%` }}
                />
              )}
              <span className="overview-bar-label">{bucket.label}</span>
            </div>
          ))}
        </div>
        )}
      </section>

      <div className="overview-split">
        <section className="panel">
          <h2 className="table-title">Top rules</h2>
          {topRules.length === 0 ? (
            <EmptyState title="No signatures triggered" description="Nothing has been blocked in the stored history." />
          ) : (
            <ul className="overview-list">
              {topRules.map((rule) => (
                <li key={rule.key}>
                  <code>{rule.key}</code>
                  <span className="badge">{rule.count}</span>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className="panel">
          <h2 className="table-title">Top sources</h2>
          {topIPs.length === 0 ? (
            <EmptyState title="No blocked sources" description="No client address appears in the stored history." />
          ) : (
            <ul className="overview-list">
              {topIPs.map((ip) => (
                <li key={ip.key}>
                  <code>{ip.key}</code>
                  <span className="badge">{ip.count}</span>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>

      <section className="panel">
        <div className="table-card-header">
          <div>
            <h2 className="table-title">Most recent blocks</h2>
            <p className="table-hint">Newest first, as stored by the API.</p>
          </div>
        </div>
        {recent.length === 0 ? (
          <EmptyState
            title={loading ? "Loading history" : "Nothing blocked yet"}
            description={
              loading
                ? "Reading the stored event ring."
                : "Send a request that trips a signature and it will appear here."
            }
          />
        ) : (
          <div className="table-responsive">
            <table className="waf-table">
              <caption className="sr-only">Most recent blocked requests</caption>
              <thead>
                <tr>
                  <th scope="col">Time</th>
                  <th scope="col">Method</th>
                  <th scope="col">Path</th>
                  <th scope="col">Source</th>
                  <th scope="col">Rule</th>
                </tr>
              </thead>
              <tbody>
                {recent.map((event, i) => (
                  <tr key={`${event.timestamp}-${event.rule_id}-${i}`}>
                    <td>{timeOf(event.timestamp)}</td>
                    <td>{event.method || "--"}</td>
                    <td title={event.path}>{event.path || "--"}</td>
                    <td>{event.remote_ip || "--"}</td>
                    <td>
                      <code>{event.rule_id || "unknown"}</code>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <p className="view-subtitle">
        <IconShield size={13} /> Sources: <code>/api/v1/events/history</code> and{" "}
        <code>/api/v1/status</code>. Nothing on this page is sampled or simulated.
      </p>
    </div>
  );
};
