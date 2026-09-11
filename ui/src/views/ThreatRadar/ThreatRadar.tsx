import React, { useState, useEffect, useMemo } from "react";
import { useWaf } from "../../context/WafContext";
import { KpiCard } from "../../components/common/KpiCard";
import { ThroughputChart } from "../../components/charts/ThroughputChart";
import { DistributionDonut } from "../../components/charts/DistributionDonut";
import type { WafEvent } from "../../api/types";

interface ThreatRadarProps {
  onSelectEvent: (e: WafEvent) => void;
}

export const ThreatRadar: React.FC<ThreatRadarProps> = ({ onSelectEvent }) => {
  const { events, status, metrics } = useWaf();

  // Synthetic throughput data that smoothly shifts every 2 seconds
  const [throughput, setThroughput] = useState<{ legit: number[]; blocked: number[] }>({
    legit: [35, 42, 38, 50, 47, 55, 62, 58, 64, 70, 68, 75, 72, 80, 85, 78, 82, 88, 92, 86],
    blocked: [2, 4, 1, 8, 3, 12, 6, 15, 9, 20, 14, 18, 11, 24, 16, 22, 19, 25, 28, 21],
  });

  useEffect(() => {
    const timer = setInterval(() => {
      setThroughput((prev) => {
        const nextLegit = [...prev.legit.slice(1), Math.round(70 + Math.random() * 25)];
        const nextBlocked = [...prev.blocked.slice(1), Math.round(10 + Math.random() * 15)];
        return { legit: nextLegit, blocked: nextBlocked };
      });
    }, 2000);
    return () => clearInterval(timer);
  }, []);

  // Category counts
  const categories = useMemo(() => {
    const counts = {
      sqli: events.filter((e) => e.rule_id.includes("sqli")).length,
      xss: events.filter((e) => e.rule_id.includes("xss")).length,
      traversal: events.filter((e) => e.rule_id.includes("traversal")).length,
      bot: events.filter((e) => e.rule_id.includes("bot")).length,
      cmdinj: events.filter((e) => e.rule_id.includes("cmdinj")).length,
      ml: events.filter((e) => e.rule_id.includes("appsec") || e.rule_id.includes("ml")).length,
    };
    const total = Object.values(counts).reduce((a, b) => a + b, 0) || 1;

    return [
      {
        label: "SQL Injection",
        count: counts.sqli,
        pct: Math.round((counts.sqli / total) * 100),
        color: "#ff0055",
      },
      {
        label: "Cross-Site Scripting",
        count: counts.xss,
        pct: Math.round((counts.xss / total) * 100),
        color: "#a855f7",
      },
      {
        label: "Path Traversal",
        count: counts.traversal,
        pct: Math.round((counts.traversal / total) * 100),
        color: "#f59e0b",
      },
      {
        label: "Bot & Scraper",
        count: counts.bot,
        pct: Math.round((counts.bot / total) * 100),
        color: "#00f2fe",
      },
      {
        label: "Command Injection",
        count: counts.cmdinj,
        pct: Math.round((counts.cmdinj / total) * 100),
        color: "#ec4899",
      },
      {
        label: "ML Anomaly",
        count: counts.ml,
        pct: Math.round((counts.ml / total) * 100),
        color: "#10b981",
      },
    ];
  }, [events]);

  const totalThreats = events.length;

  // Top Attacking IPs
  const topIPs = useMemo(() => {
    const map: Record<string, number> = {};
    events.forEach((e) => {
      map[e.remote_ip] = (map[e.remote_ip] || 0) + 1;
    });
    return Object.entries(map)
      .map(([ip, hits]) => ({ ip, hits }))
      .sort((a, b) => b.hits - a.hits)
      .slice(0, 5);
  }, [events]);

  const memMB = metrics ? Math.round(metrics.go.heap_alloc / 1024 / 1024) : 3;
  const goroutines = metrics?.go.goroutines ?? 8;
  const mode = status?.enforcement_mode ?? "blocking";

  return (
    <div className="view-container">
      {/* 4 Standardized KPI Cards */}
      <section className="kpi-grid">
        <KpiCard
          title="Enforcement Posture"
          value={status?.engine_state === "online" ? "Active" : "Connecting"}
          subtext="Fail-closed L7 filter pipeline"
          badge={mode.toUpperCase()}
          variant={mode === "blocking" ? "critical" : "warning"}
        />

        <KpiCard
          title="Threats Intercepted"
          value={totalThreats}
          subtext="Attacks mitigated in session"
          badge="Live Stream"
          variant="critical"
        />

        <KpiCard
          title="Memory Footprint"
          value={
            <>
              {memMB} <span className="unit-label">MB</span>
            </>
          }
          subtext={`${goroutines} active goroutines`}
          badge="Go Runtime"
          variant="info"
        />

        <KpiCard
          title="ML Scoring Bridge"
          value="Online"
          subtext="open-appsec contextual neural engine"
          badge="C++ Bridge"
          variant="success"
        />
      </section>

      {/* Analytics Row: Throughput & Threat Distribution */}
      <section className="analytics-grid">
        <div className="panel-card throughput-panel">
          <div className="panel-header">
            <div>
              <h2 className="panel-title">Threat Activity — Real-Time Throughput (30 min)</h2>
              <span className="panel-subtitle">
                Volume of legitimate traffic vs. blocked hostile requests
              </span>
            </div>
            <span className="live-badge">LIVE 2s</span>
          </div>

          <ThroughputChart
            legitimateData={throughput.legit}
            blockedData={throughput.blocked}
            height={180}
          />

          <div className="chart-legend">
            <div className="legend-item">
              <span className="legend-dot cyan" />
              <span>Legitimate Requests (Passed)</span>
            </div>
            <div className="legend-item">
              <span className="legend-dot crimson" />
              <span>Blocked Threat Vectors (403 Forbidden)</span>
            </div>
          </div>
        </div>

        <div className="panel-card distribution-panel">
          <div className="panel-header">
            <div>
              <h2 className="panel-title">Threat Distribution</h2>
              <span className="panel-subtitle">Breakdown by attack vector</span>
            </div>
          </div>

          <DistributionDonut segments={categories} total={totalThreats} />
        </div>
      </section>

      {/* Bottom Row: Top Attacking IPs & Recent Incidents */}
      <section className="analytics-grid">
        <div className="panel-card">
          <div className="panel-header">
            <div>
              <h2 className="panel-title">Top Hostile Sources (Source IPs)</h2>
              <span className="panel-subtitle">IP addresses triggering multi-stage violations</span>
            </div>
          </div>

          <div className="ip-list">
            {topIPs.length === 0 ? (
              <p className="text-muted">No hostile sources recorded yet.</p>
            ) : (
              topIPs.map((item, idx) => {
                const pct = Math.min(100, Math.round((item.hits / Math.max(totalThreats, 1)) * 100));
                return (
                  <div key={item.ip} className="ip-row">
                    <div className="ip-info">
                      <span className="ip-rank">#{idx + 1}</span>
                      <span className="ip-address">{item.ip}</span>
                      <span className="ip-hits">{item.hits} attacks</span>
                    </div>
                    <div className="ip-bar-track">
                      <div className="ip-bar-fill" style={{ width: `${pct}%` }} />
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        <div className="panel-card">
          <div className="panel-header">
            <div>
              <h2 className="panel-title">Recent Threat Interceptions</h2>
              <span className="panel-subtitle">Click any incident for deep forensics</span>
            </div>
          </div>

          <div className="recent-list">
            {events.slice(0, 5).map((e, idx) => (
              <button
                key={`${e.timestamp}-${idx}`}
                type="button"
                className="recent-item-btn"
                onClick={() => onSelectEvent(e)}
              >
                <div className="recent-item-left">
                  <span className="recent-rule">{e.rule_id}</span>
                  <span className="recent-path">{e.path.slice(0, 48)}{e.path.length > 48 ? "…" : ""}</span>
                </div>
                <div className="recent-item-right">
                  <span className="recent-ip">{e.remote_ip}</span>
                  <span className="recent-time">{new Date(e.timestamp).toLocaleTimeString()}</span>
                </div>
              </button>
            ))}
          </div>
        </div>
      </section>
    </div>
  );
};
