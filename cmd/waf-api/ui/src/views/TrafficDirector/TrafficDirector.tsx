import React, { useState } from "react";
import { KpiCard } from "../../components/common/KpiCard";
import { ToggleSwitch } from "../../components/common/ToggleSwitch";
import { Badge } from "../../components/common/Badge";

interface UpstreamNode {
  id: string;
  address: string;
  status: "healthy" | "degraded" | "draining";
  latency_ms: number;
  active_conns: number;
  weight: number;
}

const INITIAL_NODES: UpstreamNode[] = [
  { id: "node-1", address: "10.0.1.10:8080", status: "healthy", latency_ms: 12, active_conns: 420, weight: 100 },
  { id: "node-2", address: "10.0.1.11:8080", status: "healthy", latency_ms: 14, active_conns: 395, weight: 100 },
  { id: "node-3", address: "10.0.1.12:8080", status: "healthy", latency_ms: 18, active_conns: 410, weight: 100 },
];

export const TrafficDirector: React.FC = () => {
  const [nodes] = useState<UpstreamNode[]>(INITIAL_NODES);
  const [loadBalancingAlgo, setLoadBalancingAlgo] = useState("least_conn");

  // Traffic & Cloaking Policy switches
  const [stripServerHeader, setStripServerHeader] = useState(true);
  const [stripPoweredBy, setStripPoweredBy] = useState(true);
  const [suppressStackTraces, setSuppressStackTraces] = useState(true);
  const [tripwire404, setTripwire404] = useState(true);

  // Error page template preview state
  const [selectedErrorCode, setSelectedErrorCode] = useState<"404" | "403" | "500" | "502">("404");
  const [showPreview, setShowPreview] = useState(false);

  return (
    <div className="view-container">
      {/* 4 Standardized KPI Cards */}
      <section className="kpi-grid">
        <KpiCard
          title="Upstream Pool Health"
          value="100% Healthy"
          subtext="3/3 backend nodes responding to health checks"
          badge="Active-Active"
          variant="success"
        />
        <KpiCard
          title="Active Virtual Servers"
          value="2 VIPs"
          subtext="VIP-Prod-HTTPS (:443) & VIP-API (:8443)"
          badge="In Production"
          variant="info"
        />
        <KpiCard
          title="Server Cloaking"
          value="Enforced"
          subtext="Server & X-Powered-By headers sanitized"
          badge="Zero Fingerprint"
          variant="default"
        />
        <KpiCard
          title="404 Anomaly Tripwire"
          value="Armed"
          subtext="Directory scanning auto-jail threshold: 30/10s"
          badge="Anti-Scanner"
          variant="critical"
        />
      </section>

      {/* Traffic Filters & Server Cloaking Configuration */}
      <section className="panel-card">
        <div className="panel-header">
          <div>
            <h2 className="panel-title">Traffic Filters & Server Cloaking Policies</h2>
            <span className="panel-subtitle">
              Prevent server fingerprinting, information leakage, and brute-force directory reconnaissance
            </span>
          </div>
        </div>

        <div className="traffic-policies-grid">
          <div className="traffic-policy-item">
            <div className="policy-info">
              <strong>Strip 'Server' & 'X-Powered-By' Headers</strong>
              <p>Masks backend technology stack (Nginx, Express, ASP.NET) from adversary reconnaissance.</p>
            </div>
            <ToggleSwitch
              checked={stripServerHeader && stripPoweredBy}
              onChange={(checked) => {
                setStripServerHeader(checked);
                setStripPoweredBy(checked);
              }}
            />
          </div>

          <div className="traffic-policy-item">
            <div className="policy-info">
              <strong>Suppress Backend Stack Traces & Debug Dumps</strong>
              <p>Intercepts native 5xx backend errors and serves hardened, non-revealing error responses.</p>
            </div>
            <ToggleSwitch
              checked={suppressStackTraces}
              onChange={setSuppressStackTraces}
            />
          </div>

          <div className="traffic-policy-item">
            <div className="policy-info">
              <strong>404 Directory Scan Tripwire (Anti-Enumeration)</strong>
              <p>Monitors 404 response density; triggers automatic kernel IP block if an IP exceeds 30 404s in 10s.</p>
            </div>
            <ToggleSwitch
              checked={tripwire404}
              onChange={setTripwire404}
            />
          </div>

          <div className="traffic-policy-item">
            <div className="policy-info">
              <strong>HTTP/2 & ALPN Enforcement</strong>
              <p>Negotiates HTTP/2 with TLS ALPN; rejects malformed cleartext protocol downgrade requests.</p>
            </div>
            <ToggleSwitch checked={true} onChange={() => {}} disabled />
          </div>
        </div>
      </section>

      {/* Virtual Servers & Upstream Pool Table */}
      <section className="table-card">
        <div className="table-card-header">
          <div>
            <h2 className="table-title">Reverse Proxy: Upstream Pool (app-cluster-us-east)</h2>
            <span className="table-subtitle">
              Balancing traffic across backend application instances with active health probes
            </span>
          </div>
          <div className="algo-selector">
            <span className="algo-label">Algorithm:</span>
            <select
              className="algo-select"
              value={loadBalancingAlgo}
              onChange={(e) => setLoadBalancingAlgo(e.target.value)}
            >
              <option value="least_conn">Least Connections</option>
              <option value="round_robin">Round-Robin</option>
              <option value="ip_hash">IP Hash (Session Affinity)</option>
            </select>
          </div>
        </div>

        <div className="table-responsive">
          <table className="waf-table">
            <thead>
              <tr>
                <th>Node ID</th>
                <th>Socket Address</th>
                <th>Health Status</th>
                <th>Latency (P50)</th>
                <th>Active Connections</th>
                <th>Traffic Weight</th>
              </tr>
            </thead>
            <tbody>
              {nodes.map((node) => (
                <tr key={node.id}>
                  <td className="cell-rule">
                    <strong>{node.id}</strong>
                  </td>
                  <td className="cell-ip">{node.address}</td>
                  <td>
                    <Badge variant={node.status === "healthy" ? "success" : "critical"}>
                      {node.status.toUpperCase()}
                    </Badge>
                  </td>
                  <td className="cell-hits">{node.latency_ms} ms</td>
                  <td className="cell-score">
                    <span className="score-pill">{node.active_conns} reqs</span>
                  </td>
                  <td>{node.weight}%</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Custom Error Pages Management */}
      <section className="panel-card">
        <div className="panel-header">
          <div>
            <h2 className="panel-title">Custom Error Pages & Response Interception</h2>
            <span className="panel-subtitle">
              Brandable, secure, and fingerprint-free error templates for edge rejection
            </span>
          </div>
          <button
            type="button"
            className="btn-secondary"
            onClick={() => setShowPreview(!showPreview)}
          >
            {showPreview ? "Hide Template Preview" : "👁️ Preview Active Template"}
          </button>
        </div>

        <div className="error-codes-tabs">
          {(["404", "403", "500", "502"] as const).map((code) => (
            <button
              key={code}
              type="button"
              className={`cat-btn ${selectedErrorCode === code ? "active" : ""}`}
              onClick={() => setSelectedErrorCode(code)}
            >
              HTTP {code} {code === "404" ? "Not Found" : code === "403" ? "Forbidden" : code === "500" ? "Server Error" : "Bad Gateway"}
            </button>
          ))}
        </div>

        {showPreview && (
          <div className="error-preview-box">
            <div className="preview-browser-frame">
              <div className="preview-top-dots">
                <span className="dot red" />
                <span className="dot yellow" />
                <span className="dot green" />
                <span className="preview-url">https://application.example.com/requested-resource</span>
              </div>
              <div className="preview-content">
                <span className="preview-status-code">{selectedErrorCode}</span>
                <h3 className="preview-title">
                  {selectedErrorCode === "404"
                    ? "Page Not Found"
                    : selectedErrorCode === "403"
                    ? "Access Denied by Waffynx Security Policy"
                    : "Service Temporarily Unavailable"}
                </h3>
                <p className="preview-desc">
                  {selectedErrorCode === "404"
                    ? "The requested URL was not recognized by the routing layer. All access attempts are logged."
                    : selectedErrorCode === "403"
                    ? "Your request was inspected and flagged as potentially hostile by our edge application firewall."
                    : "The upstream application pool is undergoing maintenance or experiencing temporary load."}
                </p>
                <div className="preview-incident-id">
                  Incident ID: <code>wfx-{(Math.random() * 100000).toFixed(0)}-sec</code> • Protected by Waffynx
                </div>
              </div>
            </div>
          </div>
        )}
      </section>
    </div>
  );
};
