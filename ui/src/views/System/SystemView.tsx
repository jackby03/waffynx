import React, { useEffect, useMemo, useState } from "react";
import {
  Cpu,
  ExternalLink,
  RefreshCw,
  Save,
  ShieldAlert,
  TriangleAlert,
} from "lucide-react";
import { wafApi } from "../../api/wafApi";
import { ApiError } from "../../api/client";
import { useWaf } from "../../context/WafContext";
import { useToast } from "../../context/ToastContext";
import { KpiCard } from "../../components/common/KpiCard";
import { Badge } from "../../components/common/Badge";
import { Dialog } from "../../components/common/Dialog";
import { CodeBlock } from "../../components/common/CodeBlock";
import { Sparkline } from "../../components/charts/Sparkline";
import { formatBytes, formatDurationNs } from "../../utils/format";

export const SystemView: React.FC = () => {
  const { status, metrics, config, liveStats, refreshConfig, refreshAll } = useWaf();
  const { pushToast } = useToast();

  // Editable config fields (initialized from live GET /api/v1/config)
  const [sidecarTimeoutMs, setSidecarTimeoutMs] = useState("100");
  const [sidecarFailOpen, setSidecarFailOpen] = useState(false);
  const [appsecEnabled, setAppsecEnabled] = useState(true);
  const [appsecEngine, setAppsecEngine] = useState("basic-go");
  const [appsecLearning, setAppsecLearning] = useState(false);
  const [appsecTimeoutMs, setAppsecTimeoutMs] = useState("200");
  const [logLevel, setLogLevel] = useState("info");
  const [logFormat, setLogFormat] = useState("json");

  const [diffOpen, setDiffOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState("");

  useEffect(() => {
    if (!config) return;
    setSidecarTimeoutMs(String(config.sidecar?.timeout_ms ?? config.sidecar?.TimeoutMs ?? 100));
    setSidecarFailOpen(Boolean(config.sidecar?.fail_open ?? config.sidecar?.FailOpen ?? false));
    setAppsecEnabled(Boolean(config.appsec?.enabled ?? true));
    setAppsecEngine(config.appsec?.engine ?? "basic-go");
    setAppsecLearning(Boolean(config.appsec?.learning_mode ?? false));
    setAppsecTimeoutMs(String(config.appsec?.timeout_ms ?? 200));
    setLogLevel(config.logging?.level ?? config.logging?.Level ?? "info");
    setLogFormat(config.logging?.format ?? config.logging?.Format ?? "json");
  }, [config]);

  const patch = useMemo(() => {
    const out: Record<string, Record<string, unknown>> = {};
    if (!config) return out;

    const curSidecarTimeout = Number(config.sidecar?.timeout_ms ?? config.sidecar?.TimeoutMs ?? 100);
    const curSidecarFailOpen = Boolean(config.sidecar?.fail_open ?? config.sidecar?.FailOpen ?? false);
    const nextSidecarTimeout = Math.max(10, Number(sidecarTimeoutMs) || 100);

    if (nextSidecarTimeout !== curSidecarTimeout || sidecarFailOpen !== curSidecarFailOpen) {
      out.sidecar = {};
      if (nextSidecarTimeout !== curSidecarTimeout) out.sidecar.timeout_ms = nextSidecarTimeout;
      if (sidecarFailOpen !== curSidecarFailOpen) out.sidecar.fail_open = sidecarFailOpen;
    }

    const curAppsecEnabled = Boolean(config.appsec?.enabled ?? true);
    const curAppsecEngine = config.appsec?.engine ?? "basic-go";
    const curAppsecLearning = Boolean(config.appsec?.learning_mode ?? false);
    const curAppsecTimeout = Number(config.appsec?.timeout_ms ?? 200);
    const nextAppsecTimeout = Math.max(20, Number(appsecTimeoutMs) || 200);

    if (
      appsecEnabled !== curAppsecEnabled ||
      appsecEngine !== curAppsecEngine ||
      appsecLearning !== curAppsecLearning ||
      nextAppsecTimeout !== curAppsecTimeout
    ) {
      out.appsec = {};
      if (appsecEnabled !== curAppsecEnabled) out.appsec.enabled = appsecEnabled;
      if (appsecEngine !== curAppsecEngine) out.appsec.engine = appsecEngine;
      if (appsecLearning !== curAppsecLearning) out.appsec.learning_mode = appsecLearning;
      if (nextAppsecTimeout !== curAppsecTimeout) out.appsec.timeout_ms = nextAppsecTimeout;
    }

    const curLogLevel = config.logging?.level ?? config.logging?.Level ?? "info";
    const curLogFormat = config.logging?.format ?? config.logging?.Format ?? "json";
    if (logLevel !== curLogLevel || logFormat !== curLogFormat) {
      out.logging = {};
      if (logLevel !== curLogLevel) out.logging.level = logLevel;
      if (logFormat !== curLogFormat) out.logging.format = logFormat;
    }

    return out;
  }, [
    config,
    sidecarTimeoutMs,
    sidecarFailOpen,
    appsecEnabled,
    appsecEngine,
    appsecLearning,
    appsecTimeoutMs,
    logLevel,
    logFormat,
  ]);

  const hasChanges = Object.keys(patch).length > 0;

  const commitConfig = async () => {
    if (!hasChanges) return;
    setSaving(true);
    setSaveError("");
    try {
      await wafApi.updateConfig(patch);
      await refreshConfig();
      setDiffOpen(false);
      pushToast("ok", "Configuration updated", "Validated and persisted atomically to waffynx.yaml.");
    } catch (err) {
      setSaveError(err instanceof ApiError ? err.message : "Could not update configuration.");
    } finally {
      setSaving(false);
    }
  };

  const heapSeries = useMemo(
    () => liveStats.map((s) => s.heap_mb).filter((v): v is number => typeof v === "number"),
    [liveStats]
  );

  return (
    <div className="canvas-inner">
      <header className="view-header">
        <div>
          <h1 className="view-title" id="view-heading" tabIndex={-1}>
            System Health &amp; Configuration
          </h1>
          <p className="view-subtitle">
            Go control-plane telemetry from <code>/api/v1/status</code> and{" "}
            <code>/api/v1/metrics</code>, plus structured updates to <code>waffynx.yaml</code>.
            Secrets remain redacted server-side and are never overwritten by this UI.
          </p>
        </div>
        <div className="view-actions">
          <a href="/metrics" target="_blank" rel="noreferrer" className="btn btn-sm">
            <ExternalLink size={14} aria-hidden="true" />
            <span>Prometheus /metrics</span>
          </a>
          <button type="button" className="btn btn-sm" onClick={() => void refreshAll()}>
            <RefreshCw size={14} aria-hidden="true" />
            <span>Refresh</span>
          </button>
        </div>
      </header>

      {/* Runtime Telemetry KPIs */}
      <section className="kpi-grid">
        <KpiCard
          title="Heap Allocated"
          value={metrics ? formatBytes(metrics.go.heap_alloc) : "—"}
          subtext={metrics ? `In-use: ${formatBytes(metrics.go.heap_inuse)}` : "Waiting for metrics"}
          badge="Memory"
          tone="ml"
          sparkline={heapSeries.length >= 2 ? <Sparkline values={heapSeries} color="var(--status-ml)" /> : undefined}
        />
        <KpiCard
          title="Goroutines"
          value={metrics?.go.goroutines ?? status?.goroutines ?? "—"}
          subtext={metrics ? `Stack: ${formatBytes(metrics.go.stack_inuse ?? 0)}` : "Scheduler"}
          badge={status?.go_version ?? "Go"}
          tone="info"
        />
        <KpiCard
          title="Last GC Pause"
          value={metrics ? formatDurationNs(metrics.go.gc_pause_ns) : "—"}
          subtext={metrics?.go.num_gc !== undefined ? `${metrics.go.num_gc} total cycles` : "Garbage collector"}
          tone="ok"
        />
        <KpiCard
          title="Build Version"
          value={status?.version ?? "—"}
          subtext={status?.git_commit ? `Commit ${status.git_commit}` : "Control Plane"}
          badge={status?.config?.engine ?? "basic-go"}
          tone="default"
        />
      </section>

      {/* Configuration Editor */}
      <div className="split-2">
        <section className="panel">
          <div className="panel-header">
            <div>
              <h2 className="panel-title">Sidecar &amp; AppSec Policy</h2>
              <p className="panel-subtitle">Persisted via PUT /api/v1/config (mode 0600)</p>
            </div>
            {hasChanges && <Badge variant="high">Unsaved changes</Badge>}
          </div>
          <div className="panel-body" style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
            {sidecarFailOpen && (
              <div className="alert-banner error" role="alert">
                <span className="alert-banner-content">
                  <ShieldAlert size={16} aria-hidden="true" />
                  <span>
                    <strong>Fail-Open selected:</strong> traffic will bypass inspection if the
                    sidecar becomes unreachable (conflicts with default Fail-Closed posture).
                  </span>
                </span>
              </div>
            )}

            <div className="form-grid-2">
              <div className="field">
                <label className="field-label" htmlFor="cfg-sidecar-timeout">
                  Sidecar Timeout (ms)
                </label>
                <span className="field-hint">Max wait per request on the Unix socket</span>
                <input
                  id="cfg-sidecar-timeout"
                  type="number"
                  min={10}
                  max={5000}
                  className="input mono"
                  value={sidecarTimeoutMs}
                  onChange={(e) => setSidecarTimeoutMs(e.target.value)}
                />
              </div>

              <div className="field">
                <label className="field-label" htmlFor="cfg-appsec-timeout">
                  AppSec Scorer Timeout (ms)
                </label>
                <span className="field-hint">Max latency for external scorer bridge</span>
                <input
                  id="cfg-appsec-timeout"
                  type="number"
                  min={20}
                  max={5000}
                  className="input mono"
                  value={appsecTimeoutMs}
                  onChange={(e) => setAppsecTimeoutMs(e.target.value)}
                />
              </div>
            </div>

            <div className="form-grid-2">
              <div className="field">
                <label className="field-label" htmlFor="cfg-engine">
                  AppSec Scoring Engine
                </label>
                <select
                  id="cfg-engine"
                  className="select mono"
                  value={appsecEngine}
                  onChange={(e) => setAppsecEngine(e.target.value)}
                >
                  <option value="basic-go">basic-go (in-process deterministic)</option>
                  <option value="open-appsec">open-appsec (external Unix socket bridge)</option>
                </select>
              </div>

              <div className="field">
                <label className="field-label" htmlFor="cfg-log-level">
                  Log Level / Format
                </label>
                <div style={{ display: "flex", gap: "0.45rem" }}>
                  <select
                    id="cfg-log-level"
                    className="select"
                    value={logLevel}
                    onChange={(e) => setLogLevel(e.target.value)}
                  >
                    <option value="debug">debug</option>
                    <option value="info">info</option>
                    <option value="warn">warn</option>
                    <option value="error">error</option>
                  </select>
                  <select
                    aria-label="Log format"
                    className="select"
                    value={logFormat}
                    onChange={(e) => setLogFormat(e.target.value)}
                  >
                    <option value="json">json</option>
                    <option value="console">console</option>
                  </select>
                </div>
              </div>
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: "0.55rem" }}>
              <label style={{ display: "inline-flex", alignItems: "center", gap: "0.5rem", cursor: "pointer" }}>
                <input
                  type="checkbox"
                  checked={appsecEnabled}
                  onChange={(e) => setAppsecEnabled(e.target.checked)}
                />
                <span className="field-label">Enable inline AppSec anomaly scorer</span>
              </label>

              <label style={{ display: "inline-flex", alignItems: "center", gap: "0.5rem", cursor: "pointer" }}>
                <input
                  type="checkbox"
                  checked={appsecLearning}
                  onChange={(e) => setAppsecLearning(e.target.checked)}
                />
                <span className="field-label">Enable Behavioral Learning Mode</span>
              </label>

              <label style={{ display: "inline-flex", alignItems: "center", gap: "0.5rem", cursor: "pointer" }}>
                <input
                  type="checkbox"
                  checked={sidecarFailOpen}
                  onChange={(e) => setSidecarFailOpen(e.target.checked)}
                />
                <span className="field-label text-critical">
                  Fail-Open on sidecar timeout (not recommended)
                </span>
              </label>
            </div>

            <div>
              <button
                type="button"
                className="btn btn-primary"
                disabled={!hasChanges}
                onClick={() => {
                  setSaveError("");
                  setDiffOpen(true);
                }}
              >
                <Save size={15} aria-hidden="true" />
                <span>Review &amp; Apply Changes</span>
              </button>
            </div>
          </div>
        </section>

        {/* Read-Only Runtime & Nginx Details */}
        <section className="panel">
          <div className="panel-header">
            <div>
              <h2 className="panel-title">Deployment &amp; Socket Topology</h2>
              <p className="panel-subtitle">Read-only parameters reported by the running binary</p>
            </div>
            <Cpu size={16} color="var(--text-muted)" aria-hidden="true" />
          </div>
          <div className="panel-body">
            <dl className="detail-grid">
              <div className="detail-cell">
                <dt>Control Plane Listen</dt>
                <dd className="mono">{config?.api?.listen ?? ":9090"}</dd>
              </div>
              <div className="detail-cell">
                <dt>Token TTL</dt>
                <dd className="mono">{config?.api?.auth?.token_ttl ?? 3600}s</dd>
              </div>
              <div className="detail-cell wide">
                <dt>Sidecar Unix Socket</dt>
                <dd className="mono">
                  {config?.sidecar?.socket_path ?? config?.sidecar?.SocketPath ?? "/opt/waffynx/waffynx.sock"}
                </dd>
              </div>
              <div className="detail-cell">
                <dt>Nginx HTTP Listener</dt>
                <dd className="mono">
                  {config?.nginx?.http_listen ?? config?.nginx?.HTTPListen ?? ":8080"}
                </dd>
              </div>
              <div className="detail-cell">
                <dt>Nginx TLS Listener</dt>
                <dd className="mono">
                  {config?.nginx?.tls_listen ?? config?.nginx?.TLSListen ?? ":8443"}
                </dd>
              </div>
              <div className="detail-cell">
                <dt>HTTP/2 Support</dt>
                <dd>
                  <Badge variant={config?.nginx?.enable_http2 ?? config?.nginx?.EnableHTTP2 ? "ok" : "neutral"}>
                    {config?.nginx?.enable_http2 ?? config?.nginx?.EnableHTTP2 ? "Enabled" : "Off"}
                  </Badge>
                </dd>
              </div>
              <div className="detail-cell">
                <dt>Build Timestamp</dt>
                <dd className="mono">{status?.build_time || "dev"}</dd>
              </div>
            </dl>
          </div>
        </section>
      </div>

      {/* Config Diff Confirmation Dialog */}
      <Dialog
        open={diffOpen}
        onClose={() => setDiffOpen(false)}
        eyebrow="Configuration Commit"
        title="Review partial configuration patch"
        variant="modal"
        closedby="closerequest"
        footer={
          <>
            <button type="button" className="btn" onClick={() => setDiffOpen(false)} disabled={saving}>
              Cancel
            </button>
            <button
              type="button"
              className="btn btn-primary"
              disabled={saving}
              aria-busy={saving}
              onClick={() => void commitConfig()}
            >
              {saving ? "Persisting…" : "Apply Patch"}
            </button>
          </>
        }
      >
        <p className="text-secondary" style={{ fontSize: "0.84rem" }}>
          Only the modified keys below will be deep-merged into <code>waffynx.yaml</code> and
          validated before writing to disk:
        </p>

        {sidecarFailOpen && (
          <div className="alert-banner warn" role="alert">
            <span className="alert-banner-content">
              <TriangleAlert size={15} aria-hidden="true" />
              <span>Warning: enabling sidecar fail_open allows uninspected traffic if the sidecar stops.</span>
            </span>
          </div>
        )}

        {saveError && (
          <div className="alert-banner error" role="alert">
            {saveError}
          </div>
        )}

        <CodeBlock label="PUT /api/v1/config payload" copyText={JSON.stringify(patch, null, 2)}>
          {JSON.stringify(patch, null, 2)}
        </CodeBlock>
      </Dialog>
    </div>
  );
};
