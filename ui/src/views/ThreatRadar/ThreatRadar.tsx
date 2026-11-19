import React from "react";
import { useWaf } from "../../context/WafContext";
import { KpiCard } from "../../components/common/KpiCard";
import { EmptyState } from "../../components/common/EmptyState";
import { IconShield } from "../../components/common/Icons";

// ThreatRadar shows only what the control plane actually reports.
//
// It used to draw a 30-minute throughput chart and a distribution donut from
// Math.random(), and to label the scorer "C++ Bridge / open-appsec" when the
// engine has been pure Go since the vendored engine was removed. A dashboard that
// invents its own telemetry is worse than an empty one: it cannot be trusted
// during an incident.
export const ThreatRadar: React.FC = () => {
  const { status, metrics, events, rules, loadError } = useWaf();

  const memoryMB = metrics ? Math.round(metrics.go.heap_alloc / 1024 / 1024) : null;
  const goroutines = metrics?.go.goroutines ?? status?.goroutines ?? null;
  const engine = status?.config?.engine ?? "unknown";
  const blocked = events.filter((e) => e.action === "deny").length;
  const recent = events.slice(0, 8);

  return (
    <div className="view-stack">
      <header className="view-header">
        <div>
          <h1 className="view-title">Threat Radar</h1>
          <p className="view-subtitle">
            Live values reported by the control plane. No time series is drawn because the API
            does not expose history yet; the feed below is the current session only.
          </p>
        </div>
      </header>

      {loadError && (
        <div className="alert alert-error" role="alert">
          {loadError}
        </div>
      )}

      <section className="kpi-grid">
        <KpiCard
          title="Managed signatures"
          value={rules.length}
          subtext="Compiled into one Aho–Corasick automaton"
          badge="Deterministic"
          variant="info"
        />
        <KpiCard
          title="Blocked this session"
          value={blocked}
          subtext="Events received since the dashboard connected"
          badge="Live feed"
          variant="critical"
        />
        <KpiCard
          title="Scorer"
          value={engine}
          subtext="In-process; no external engine attached"
          badge="Configured engine"
          variant="success"
        />
        <KpiCard
          title="Memory footprint"
          value={memoryMB === null ? "—" : `${memoryMB} MB`}
          subtext={goroutines === null ? "Go runtime" : `${goroutines} goroutines`}
          badge="Go runtime"
          variant="warning"
        />
      </section>

      <div className="table-card">
        <div className="table-card-header">
          <div>
            <h2 className="table-title">Current session</h2>
            <span className="table-subtitle">
              {events.length} event{events.length === 1 ? "" : "s"} received
            </span>
          </div>
        </div>

        {recent.length === 0 ? (
          <EmptyState
            icon={<IconShield size={28} />}
            title="No events in this session"
            description="Events appear here as the WAF blocks traffic. They are not persisted: the API streams them, it does not store history yet."
          />
        ) : (
          <div className="table-scroll" role="region" aria-label="Recent events" tabIndex={0}>
            <table className="waf-table">
              <caption className="sr-only">Recent security events</caption>
              <thead>
                <tr>
                  <th scope="col">Time</th>
                  <th scope="col">Rule</th>
                  <th scope="col">Source</th>
                  <th scope="col">Path</th>
                </tr>
              </thead>
              <tbody>
                {recent.map((event, index) => (
                  <tr key={`${event.timestamp}-${index}`}>
                    <td>{new Date(event.timestamp).toLocaleTimeString()}</td>
                    <td>
                      <code>{event.rule_id || "—"}</code>
                    </td>
                    <td className="text-muted">{event.remote_ip || "—"}</td>
                    <td>
                      <code>{event.path || "—"}</code>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
