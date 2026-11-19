import React, { useCallback, useEffect, useState } from "react";
import { Lock, Network, Plus, RefreshCw, Shield, ShieldOff, Trash2 } from "lucide-react";
import type { ZeroTrustPolicy } from "../../api/types";
import { wafApi } from "../../api/wafApi";
import { ApiError } from "../../api/client";
import { useWaf } from "../../context/WafContext";
import { useToast } from "../../context/ToastContext";
import { Badge } from "../../components/common/Badge";
import { Dialog } from "../../components/common/Dialog";
import { EmptyState } from "../../components/common/EmptyState";
import { KpiCard } from "../../components/common/KpiCard";

export const ZeroTrustView: React.FC = () => {
  const { topology, exclusions, refreshTopology, refreshExclusions, createExclusion, deleteExclusion } =
    useWaf();
  const { pushToast } = useToast();

  const [policies, setPolicies] = useState<ZeroTrustPolicy[]>([]);
  const [loading, setLoading] = useState(true);
  const [ztDialogOpen, setZtDialogOpen] = useState(false);
  const [exDialogOpen, setExDialogOpen] = useState(false);
  const [saving, setSaving] = useState(false);

  // Zero-Trust Policy form state
  const [ztName, setZtName] = useState("");
  const [ztHost, setZtHost] = useState("");
  const [ztPathPrefix, setZtPathPrefix] = useState("/admin");
  const [ztPriority, setZtPriority] = useState(100);
  const [ztRequireJWT, setZtRequireJWT] = useState(true);
  const [ztScopes, setZtScopes] = useState("admin");
  const [ztCIDRs, setZtCIDRs] = useState("");
  const [ztBlockedCountries, setZtBlockedCountries] = useState("");
  const [ztDeviceHeader, setZtDeviceHeader] = useState("");
  const [ztShadowMode, setZtShadowMode] = useState(false);

  // Exclusion form state
  const [exName, setExName] = useState("");
  const [exRuleID, setExRuleID] = useState("");
  const [exHost, setExHost] = useState("");
  const [exPathExact, setExPathExact] = useState("");
  const [exPathPrefix, setExPathPrefix] = useState("");
  const [exParam, setExParam] = useState("");
  const [exReason, setExReason] = useState("");

  const loadPolicies = useCallback(async () => {
    setLoading(true);
    try {
      const [list] = await Promise.all([
        wafApi.listZeroTrustPolicies(),
        refreshTopology().catch(() => {}),
        refreshExclusions().catch(() => {}),
      ]);
      setPolicies(list);
    } catch {
      setPolicies([]);
    } finally {
      setLoading(false);
    }
  }, [refreshTopology, refreshExclusions]);

  useEffect(() => {
    void loadPolicies();
  }, [loadPolicies]);

  const splitCSV = (raw: string): string[] =>
    raw
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);

  const handleCreateZT = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!ztName.trim()) {
      pushToast("error", "Policy name is required");
      return;
    }
    setSaving(true);
    try {
      await wafApi.createZeroTrustPolicy({
        name: ztName.trim(),
        host: ztHost.trim() || undefined,
        path_prefix: ztPathPrefix.trim() || "/",
        enabled: true,
        priority: Number(ztPriority) || 100,
        require_jwt: ztRequireJWT,
        required_scopes: splitCSV(ztScopes),
        allowed_cidrs: splitCSV(ztCIDRs),
        blocked_countries: splitCSV(ztBlockedCountries),
        require_device_header: ztDeviceHeader.trim() || undefined,
        shadow_mode: ztShadowMode,
      });
      pushToast("ok", "Zero-Trust policy published", "Hot-reloaded to all waf-engine replicas via Redis Pub/Sub.");
      setZtDialogOpen(false);
      setZtName("");
      setZtHost("");
      setZtPathPrefix("/admin");
      await loadPolicies();
    } catch (err) {
      pushToast("error", "Failed to save Zero-Trust policy", err instanceof ApiError ? err.message : "Request failed");
    } finally {
      setSaving(false);
    }
  };

  const handleDeleteZT = async (p: ZeroTrustPolicy) => {
    try {
      await wafApi.deleteZeroTrustPolicy(p.id);
      pushToast("info", `Deleted policy ${p.name}`);
      await loadPolicies();
    } catch (err) {
      pushToast("error", "Delete failed", err instanceof ApiError ? err.message : "Request failed");
    }
  };

  const handleCreateEx = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!exRuleID.trim()) {
      pushToast("error", "Rule ID is required (use * for all rules)");
      return;
    }
    setSaving(true);
    try {
      await createExclusion({
        name: exName.trim() || `Exclusion for ${exRuleID.trim()}`,
        rule_id: exRuleID.trim(),
        host: exHost.trim() || undefined,
        path_exact: exPathExact.trim() || undefined,
        path_prefix: exPathPrefix.trim() || undefined,
        param: exParam.trim() || undefined,
        reason: exReason.trim() || undefined,
        enabled: true,
      });
      pushToast("ok", "Exclusion published", "Applied lock-free on Data Plane.");
      setExDialogOpen(false);
      setExName("");
      setExRuleID("");
      setExHost("");
      setExPathExact("");
      setExPathPrefix("");
      setExParam("");
      setExReason("");
    } catch (err) {
      pushToast("error", "Failed to create exclusion", err instanceof ApiError ? err.message : "Request failed");
    } finally {
      setSaving(false);
    }
  };

  const handleDeleteEx = async (id: string) => {
    try {
      await deleteExclusion(id);
      pushToast("info", `Removed exclusion ${id}`);
    } catch (err) {
      pushToast("error", "Delete failed", err instanceof ApiError ? err.message : "Request failed");
    }
  };

  const dp = topology?.planes.data_plane;
  const cp = topology?.planes.control_plane;
  const obs = topology?.planes.observability_plane;

  return (
    <div className="canvas-inner">
      <header className="view-header">
        <div>
          <h1 className="view-title" id="view-heading" tabIndex={-1}>
            Zero Trust, Mesh &amp; Exclusions
          </h1>
          <p className="view-subtitle">
            NIST SP 800-207 continuous authorization (<code className="mono">ext_authz</code>), live Envoy xDS mesh
            topology, and lock-free false-positive exclusions.
          </p>
        </div>

        <div className="view-actions">
          <button type="button" className="btn btn-sm" onClick={() => void loadPolicies()}>
            <RefreshCw size={14} aria-hidden="true" />
            <span>Refresh</span>
          </button>
          <button type="button" className="btn btn-sm" onClick={() => setExDialogOpen(true)}>
            <ShieldOff size={14} aria-hidden="true" />
            <span>New Exclusion</span>
          </button>
          <button type="button" className="btn btn-primary btn-sm" onClick={() => setZtDialogOpen(true)}>
            <Plus size={14} aria-hidden="true" />
            <span>New Zero-Trust Policy</span>
          </button>
        </div>
      </header>

      {/* Multi-Plane Orchestrated Topology KPIs */}
      <section className="kpi-grid">
        <KpiCard
          title="Deployment Mode"
          value={topology?.mode === "distributed" ? "Distributed" : "Standalone"}
          subtext={dp?.pep === "envoy-xds" ? "Envoy PEP + gRPC ext_proc/ext_authz" : "Nginx C module + UDS sidecar"}
          badge={topology?.mtls_enabled ? "mTLS TLS 1.3" : "Dev Mesh"}
          tone={topology?.mtls_enabled ? "ok" : "info"}
        />
        <KpiCard
          title="Envoy xDS Nodes"
          value={dp?.connected_nodes?.length ?? 0}
          subtext={`xDS Snapshot v${dp?.xds_version ?? 0} · Policy Rev #${topology?.policy_revision ?? 0}`}
          badge={dp?.xds_enabled ? "xDS Active" : "xDS Off"}
          tone={dp?.xds_enabled ? "ok" : "default"}
        />
        <KpiCard
          title="Control & State"
          value={cp?.postgres_healthy ? "PostgreSQL" : "Local YAML"}
          subtext={`Redis Hot-Reload: ${dp?.redis_healthy ? "Connected" : dp?.redis_enabled ? "Degraded" : "Disabled"}`}
          badge={cp?.postgres_healthy ? "Durable" : "File"}
          tone={cp?.postgres_healthy ? "ok" : "default"}
        />
        <KpiCard
          title="Observability Plane"
          value={obs?.clickhouse_healthy ? "ClickHouse" : "SSE Ring"}
          subtext={`NATS JetStream: ${obs?.nats_enabled ? "Async Stream" : "In-Process"}`}
          badge={obs?.clickhouse_healthy ? "Async Bulk" : "Memory"}
          tone={obs?.clickhouse_healthy ? "ok" : "info"}
        />
      </section>

      {/* Connected Envoy Replicas */}
      {dp?.xds_enabled && (
        <section className="panel">
          <div className="panel-header">
            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
              <Network size={16} aria-hidden="true" />
              <h2 className="panel-title">Connected Envoy Edge PEP Replicas (ADS xDS)</h2>
            </div>
            <Badge variant="info">v{dp.xds_version}</Badge>
          </div>
          <div className="panel-body">
            {dp.connected_nodes.length === 0 ? (
              <p className="text-muted">Waiting for Envoy Data Plane nodes to connect on xDS gRPC…</p>
            ) : (
              <div style={{ display: "flex", flexWrap: "wrap", gap: "0.65rem" }}>
                {dp.connected_nodes.map((n) => (
                  <div
                    key={n.node_id}
                    className="panel"
                    style={{ padding: "0.65rem 0.9rem", background: "var(--surface-elevated)" }}
                  >
                    <div className="mono" style={{ fontWeight: 600 }}>
                      {n.node_id}
                    </div>
                    <div className="text-muted" style={{ fontSize: "0.75rem" }}>
                      {n.streams} active ADS stream{n.streams === 1 ? "" : "s"}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </section>
      )}

      {/* Zero-Trust ext_authz Policies */}
      <section className="panel" aria-busy={loading}>
        <div className="panel-header">
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <Lock size={16} aria-hidden="true" />
            <h2 className="panel-title">Zero-Trust Authorization Policies (ext_authz)</h2>
          </div>
          <Badge variant="neutral">{policies.length} active</Badge>
        </div>

        {policies.length === 0 ? (
          <EmptyState
            icon={<Shield size={22} />}
            title="No Zero-Trust route policies configured"
            description="Add a policy to enforce continuous JWT/OIDC verification, required scopes, CIDR allowlists, GeoIP blocks, or device posture checks before requests reach your upstream."
          />
        ) : (
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th scope="col">Priority</th>
                  <th scope="col">Policy</th>
                  <th scope="col">Target Scope</th>
                  <th scope="col">Controls</th>
                  <th scope="col">Mode</th>
                  <th scope="col" style={{ textAlign: "right" }}>
                    Action
                  </th>
                </tr>
              </thead>
              <tbody>
                {policies.map((p) => (
                  <tr key={p.id}>
                    <td className="mono">{p.priority}</td>
                    <td>
                      <div style={{ fontWeight: 600 }}>{p.name}</div>
                      <div className="mono text-muted" style={{ fontSize: "0.72rem" }}>
                        {p.id}
                      </div>
                    </td>
                    <td className="mono">
                      {p.host || "*"}
                      {p.path_prefix}
                    </td>
                    <td>
                      <div style={{ display: "flex", flexWrap: "wrap", gap: "0.3rem" }}>
                        {p.require_jwt && <Badge variant="info">JWT Required</Badge>}
                        {p.required_scopes && p.required_scopes.length > 0 && (
                          <Badge variant="neutral">scopes: {p.required_scopes.join(",")}</Badge>
                        )}
                        {p.allowed_cidrs && p.allowed_cidrs.length > 0 && (
                          <Badge variant="neutral">CIDR: {p.allowed_cidrs.join(",")}</Badge>
                        )}
                        {p.blocked_countries && p.blocked_countries.length > 0 && (
                          <Badge variant="critical">Block Geo: {p.blocked_countries.join(",")}</Badge>
                        )}
                        {p.require_device_header && <Badge variant="medium">Device: {p.require_device_header}</Badge>}
                      </div>
                    </td>
                    <td>
                      <Badge variant={p.shadow_mode ? "medium" : p.enabled ? "ok" : "neutral"}>
                        {p.shadow_mode ? "Shadow" : p.enabled ? "Enforce" : "Disabled"}
                      </Badge>
                    </td>
                    <td style={{ textAlign: "right" }}>
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm"
                        aria-label={`Delete Zero-Trust policy ${p.name}`}
                        onClick={() => void handleDeleteZT(p)}
                      >
                        <Trash2 size={14} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* False-Positive Exclusions */}
      <section className="panel">
        <div className="panel-header">
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <ShieldOff size={16} aria-hidden="true" />
            <h2 className="panel-title">False-Positive Exclusions (atomic.Pointer Hot-Reload)</h2>
          </div>
          <Badge variant="neutral">{exclusions.length} active</Badge>
        </div>

        {exclusions.length === 0 ? (
          <EmptyState
            icon={<ShieldOff size={22} />}
            title="No active rule exclusions"
            description="Create an exclusion here or in 1 click directly from any blocked event in Security Events."
          />
        ) : (
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th scope="col">Rule ID</th>
                  <th scope="col">Name</th>
                  <th scope="col">Match Scope</th>
                  <th scope="col">Reason</th>
                  <th scope="col" style={{ textAlign: "right" }}>
                    Action
                  </th>
                </tr>
              </thead>
              <tbody>
                {exclusions.map((ex) => (
                  <tr key={ex.id}>
                    <td>
                      <span className="rule-chip">{ex.rule_id}</span>
                    </td>
                    <td>{ex.name}</td>
                    <td className="mono">
                      {[
                        ex.host && `host=${ex.host}`,
                        ex.path_exact && `path=${ex.path_exact}`,
                        ex.path_prefix && `prefix=${ex.path_prefix}`,
                        ex.param && `param=${ex.param}`,
                      ]
                        .filter(Boolean)
                        .join(" · ") || "—"}
                    </td>
                    <td className="text-secondary">{ex.reason || "—"}</td>
                    <td style={{ textAlign: "right" }}>
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm"
                        aria-label={`Delete exclusion ${ex.id}`}
                        onClick={() => void handleDeleteEx(ex.id)}
                      >
                        <Trash2 size={14} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Create Zero-Trust Policy Dialog */}
      <Dialog
        open={ztDialogOpen}
        onClose={() => setZtDialogOpen(false)}
        eyebrow="NIST SP 800-207 · ext_authz"
        title="New Zero-Trust Policy"
      >
        <form onSubmit={(e) => void handleCreateZT(e)} style={{ display: "flex", flexDirection: "column", gap: "0.85rem" }}>
          <div className="field">
            <label className="field-label" htmlFor="zt-name">Policy Name</label>
            <input id="zt-name" className="input" required value={ztName} onChange={(e) => setZtName(e.target.value)} placeholder="Admin Portal Zero Trust" />
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 90px", gap: "0.65rem" }}>
            <div className="field">
              <label className="field-label" htmlFor="zt-host">Host (optional)</label>
              <input id="zt-host" className="input mono" value={ztHost} onChange={(e) => setZtHost(e.target.value)} placeholder="app.example.test" />
            </div>
            <div className="field">
              <label className="field-label" htmlFor="zt-path">Path Prefix</label>
              <input id="zt-path" className="input mono" value={ztPathPrefix} onChange={(e) => setZtPathPrefix(e.target.value)} placeholder="/admin" />
            </div>
            <div className="field">
              <label className="field-label" htmlFor="zt-prio">Priority</label>
              <input id="zt-prio" type="number" className="input mono" value={ztPriority} onChange={(e) => setZtPriority(Number(e.target.value))} />
            </div>
          </div>
          <div style={{ display: "flex", gap: "1.2rem" }}>
            <label style={{ display: "flex", alignItems: "center", gap: "0.45rem", cursor: "pointer" }}>
              <input type="checkbox" checked={ztRequireJWT} onChange={(e) => setZtRequireJWT(e.target.checked)} />
              <span>Require Valid JWT Bearer Token</span>
            </label>
            <label style={{ display: "flex", alignItems: "center", gap: "0.45rem", cursor: "pointer" }}>
              <input type="checkbox" checked={ztShadowMode} onChange={(e) => setZtShadowMode(e.target.checked)} />
              <span>Shadow / Observe Mode</span>
            </label>
          </div>
          <div className="field">
            <label className="field-label" htmlFor="zt-scopes">Required Scopes (comma-separated)</label>
            <input id="zt-scopes" className="input mono" value={ztScopes} onChange={(e) => setZtScopes(e.target.value)} placeholder="admin, write" />
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.65rem" }}>
            <div className="field">
              <label className="field-label" htmlFor="zt-cidrs">Allowed CIDRs (optional)</label>
              <input id="zt-cidrs" className="input mono" value={ztCIDRs} onChange={(e) => setZtCIDRs(e.target.value)} placeholder="10.0.0.0/8, 172.16.0.0/12" />
            </div>
            <div className="field">
              <label className="field-label" htmlFor="zt-cc">Blocked Countries ISO (optional)</label>
              <input id="zt-cc" className="input mono" value={ztBlockedCountries} onChange={(e) => setZtBlockedCountries(e.target.value)} placeholder="KP, IR" />
            </div>
          </div>
          <div className="field">
            <label className="field-label" htmlFor="zt-dev">Required Device Posture Header (optional)</label>
            <input id="zt-dev" className="input mono" value={ztDeviceHeader} onChange={(e) => setZtDeviceHeader(e.target.value)} placeholder="x-device-trust: verified" />
          </div>
          <div style={{ display: "flex", justifyContent: "flex-end", gap: "0.5rem", marginTop: "0.5rem" }}>
            <button type="button" className="btn" onClick={() => setZtDialogOpen(false)}>Cancel</button>
            <button type="submit" className="btn btn-primary" disabled={saving}>
              {saving ? "Publishing…" : "Publish Policy"}
            </button>
          </div>
        </form>
      </Dialog>

      {/* Create Exclusion Dialog */}
      <Dialog
        open={exDialogOpen}
        onClose={() => setExDialogOpen(false)}
        eyebrow="False-Positive Tuning"
        title="New Rule Exclusion"
      >
        <form onSubmit={(e) => void handleCreateEx(e)} style={{ display: "flex", flexDirection: "column", gap: "0.85rem" }}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.65rem" }}>
            <div className="field">
              <label className="field-label" htmlFor="ex-rule">Rule ID (or *)</label>
              <input id="ex-rule" className="input mono" required value={exRuleID} onChange={(e) => setExRuleID(e.target.value)} placeholder="WAF-SQLI-001" />
            </div>
            <div className="field">
              <label className="field-label" htmlFor="ex-name">Label</label>
              <input id="ex-name" className="input" value={exName} onChange={(e) => setExName(e.target.value)} placeholder="Allow GraphQL endpoint" />
            </div>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.65rem" }}>
            <div className="field">
              <label className="field-label" htmlFor="ex-host">Host (optional)</label>
              <input id="ex-host" className="input mono" value={exHost} onChange={(e) => setExHost(e.target.value)} placeholder="app.example.test" />
            </div>
            <div className="field">
              <label className="field-label" htmlFor="ex-param">Query Param (optional)</label>
              <input id="ex-param" className="input mono" value={exParam} onChange={(e) => setExParam(e.target.value)} placeholder="filter" />
            </div>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.65rem" }}>
            <div className="field">
              <label className="field-label" htmlFor="ex-exact">Exact Path (optional)</label>
              <input id="ex-exact" className="input mono" value={exPathExact} onChange={(e) => setExPathExact(e.target.value)} placeholder="/api/search" />
            </div>
            <div className="field">
              <label className="field-label" htmlFor="ex-prefix">Path Prefix (optional)</label>
              <input id="ex-prefix" className="input mono" value={exPathPrefix} onChange={(e) => setExPathPrefix(e.target.value)} placeholder="/webhooks/" />
            </div>
          </div>
          <div className="field">
            <label className="field-label" htmlFor="ex-reason">Justification</label>
            <input id="ex-reason" className="input" value={exReason} onChange={(e) => setExReason(e.target.value)} placeholder="Verified benign traffic pattern" />
          </div>
          <div style={{ display: "flex", justifyContent: "flex-end", gap: "0.5rem", marginTop: "0.5rem" }}>
            <button type="button" className="btn" onClick={() => setExDialogOpen(false)}>Cancel</button>
            <button type="submit" className="btn btn-primary" disabled={saving}>
              {saving ? "Publishing…" : "Create Exclusion"}
            </button>
          </div>
        </form>
      </Dialog>
    </div>
  );
};
