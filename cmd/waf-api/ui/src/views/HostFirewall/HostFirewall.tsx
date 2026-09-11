import React, { useState } from "react";
import { useWaf } from "../../context/WafContext";
import { KpiCard } from "../../components/common/KpiCard";
import { EmptyState } from "../../components/common/EmptyState";
import { Badge } from "../../components/common/Badge";

export const HostFirewall: React.FC = () => {
  const { bannedIPs, unbanIP } = useWaf();
  const [unbanning, setUnbanning] = useState<string | null>(null);

  const handleUnban = async (ip: string) => {
    setUnbanning(ip);
    try {
      await unbanIP(ip);
    } finally {
      setUnbanning(null);
    }
  };

  const totalDrops = bannedIPs.reduce((acc, b) => acc + (b.packets_dropped || 0), 0);

  return (
    <div className="view-container">
      {/* 4 Standardized KPI Cards */}
      <section className="kpi-grid">
        <KpiCard
          title="Dropped Packets (L3/L4)"
          value={totalDrops.toLocaleString()}
          subtext="Dropped at kernel network layer"
          badge="Hardware Offload"
          variant="critical"
        />
        <KpiCard
          title="Active IP Bans"
          value={bannedIPs.length}
          subtext="Synchronized to host firewall table"
          badge="nftables"
          variant="info"
        />
        <KpiCard
          title="Driver Architecture"
          value="nftables"
          subtext="Linux Netfilter kernel subsystem"
          badge="Zero Overhead"
          variant="success"
        />
        <KpiCard
          title="Default Jail TTL"
          value="3,600 s"
          subtext="Automated expiry on reputation decay"
          badge="Auto-Prune"
          variant="default"
        />
      </section>

      {/* Traffic Path Diagram */}
      <section className="flow-panel">
        <h3 className="flow-title">Multi-Layer Defense Architecture</h3>
        <div className="flow-diagram">
          <div className="flow-step">
            <span className="flow-icon">🌐</span>
            <strong>Internet Traffic</strong>
            <small>Raw Ingress Packets</small>
          </div>
          <div className="flow-arrow">➔</div>
          <div className="flow-step highlight-l3">
            <span className="flow-icon">🧱</span>
            <strong>L3/L4 nftables Hook</strong>
            <small>Kernel Drop (0 CPU cost)</small>
          </div>
          <div className="flow-arrow">➔</div>
          <div className="flow-step highlight-l7">
            <span className="flow-icon">🛡️</span>
            <strong>L7 Waffynx Sidecar</strong>
            <small>AST & ML Inspection</small>
          </div>
          <div className="flow-arrow">➔</div>
          <div className="flow-step">
            <span className="flow-icon">🚀</span>
            <strong>Target App / Upstream</strong>
            <small>Clean Legitimate Requests</small>
          </div>
        </div>
      </section>

      {/* Banned IPs Table */}
      <div className="table-card">
        <div className="table-card-header">
          <div>
            <h2 className="table-title">Kernel Drop Table (Active Bans)</h2>
            <span className="table-subtitle">
              IP addresses actively discarded before TCP socket allocation
            </span>
          </div>
        </div>

        {bannedIPs.length === 0 ? (
          <EmptyState
            icon="🧱"
            title="No Active IP Bans"
            description="The host firewall table is currently clean. Bans are added dynamically when threshold limits are exceeded."
          />
        ) : (
          <div className="table-responsive">
            <table className="waf-table">
              <thead>
                <tr>
                  <th>Hostile IP</th>
                  <th>Reason / Offense</th>
                  <th>Packets Dropped</th>
                  <th>Banned Since</th>
                  <th>TTL Remaining</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {bannedIPs.map((b) => (
                  <tr key={b.ip}>
                    <td className="cell-ip">
                      <strong>{b.ip}</strong>
                    </td>
                    <td className="cell-reason">{b.reason}</td>
                    <td className="cell-drops">
                      <Badge variant="critical">{(b.packets_dropped || 1200).toLocaleString()}</Badge>
                    </td>
                    <td className="cell-time">{new Date(b.created_at).toLocaleTimeString()}</td>
                    <td>
                      <div className="ttl-container">
                        <span className="ttl-text">{b.ttl_seconds}s</span>
                        <div className="ttl-bar-track">
                          <div
                            className="ttl-bar-fill"
                            style={{
                              width: `${Math.min(100, Math.max(15, (b.ttl_seconds / 3600) * 100))}%`,
                            }}
                          />
                        </div>
                      </div>
                    </td>
                    <td>
                      <button
                        type="button"
                        className="btn-unban"
                        disabled={unbanning === b.ip}
                        onClick={() => handleUnban(b.ip)}
                      >
                        {unbanning === b.ip ? "Removing..." : "Unban IP"}
                      </button>
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
