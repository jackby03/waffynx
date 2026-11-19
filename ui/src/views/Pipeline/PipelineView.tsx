import React, { useMemo } from "react";
import { ArrowRight, Layers, Shield } from "lucide-react";
import { useWaf } from "../../context/WafContext";
import { KpiCard } from "../../components/common/KpiCard";
import { Badge } from "../../components/common/Badge";
import { EmptyState } from "../../components/common/EmptyState";

export const PipelineView: React.FC = () => {
  const { plugins, rules, status } = useWaf();

  const sortedPlugins = useMemo(
    () => [...plugins].sort((a, b) => a.priority - b.priority || a.name.localeCompare(b.name)),
    [plugins]
  );

  const phases = useMemo(() => {
    const map = new Map<string, number>();
    for (const p of plugins) {
      map.set(p.phase, (map.get(p.phase) ?? 0) + 1);
    }
    return map;
  }, [plugins]);

  const stages = [
    {
      num: "01",
      name: "Nginx C Module",
      detail: "ACCESS phase intercept · zero-copy header & body capture",
      badge: "C / Native",
      accent: false,
    },
    {
      num: "02",
      name: "Custom L7 Rules",
      detail: "Operator policies & IP bans evaluated first",
      badge: "Dynamic",
      accent: true,
    },
    {
      num: "03",
      name: "Managed Catalog",
      detail: `${rules.length} signatures in one Aho-Corasick automaton`,
      badge: "Deterministic",
      accent: true,
    },
    {
      num: "04",
      name: "Plugin Chain",
      detail: `${plugins.length} registered inspection modules by priority`,
      badge: "Extensible",
      accent: true,
    },
    {
      num: "05",
      name: "AppSec Scorer",
      detail: `Engine: ${status?.config?.engine ?? "basic-go"} · Fail-closed policy`,
      badge: "Anomaly",
      accent: false,
    },
  ];

  return (
    <div className="canvas-inner">
      <header className="view-header">
        <div>
          <h1 className="view-title" id="view-heading" tabIndex={-1}>
            Inspection Pipeline &amp; Plugins
          </h1>
          <p className="view-subtitle">
            Ordered execution stages inside the Waffynx data plane and registered plugin metadata
            reported by <code>/api/v1/plugins</code>.
          </p>
        </div>
      </header>

      <section className="kpi-grid">
        <KpiCard title="Registered Plugins" value={plugins.length} subtext="Compiled into sidecar registry" tone="info" />
        <KpiCard title="Pre-Request Phase" value={phases.get("pre_request") ?? 0} subtext="Inspect before upstream" tone="ok" />
        <KpiCard title="Catalog Signatures" value={rules.length} subtext="Evaluated prior to plugin chain" tone="ml" />
        <KpiCard title="IPC Transport" value="0600 Unix" subtext="Sub-2ms P99 target budget" badge="Zero-Copy" tone="default" />
      </section>

      {/* Pipeline Visual Flow */}
      <section className="panel">
        <div className="panel-header">
          <div>
            <h2 className="panel-title">Request Evaluation Flow</h2>
            <p className="panel-subtitle">
              Requests short-circuit immediately on any blocking verdict (HTTP 403)
            </p>
          </div>
        </div>
        <div className="panel-body">
          <div className="pipeline-flow">
            {stages.map((st, idx) => (
              <div key={st.num} className={`pipeline-node ${st.accent ? "accent" : ""}`}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <span className="mono text-muted" style={{ fontSize: "0.72rem", fontWeight: 700 }}>
                    STAGE {st.num}
                  </span>
                  <Badge variant={st.accent ? "info" : "neutral"}>{st.badge}</Badge>
                </div>
                <div style={{ fontWeight: 700, fontSize: "0.9rem", display: "flex", alignItems: "center", gap: "0.35rem" }}>
                  <span>{st.name}</span>
                  {idx < stages.length - 1 && (
                    <ArrowRight size={13} color="var(--text-muted)" aria-hidden="true" />
                  )}
                </div>
                <p className="text-secondary" style={{ fontSize: "0.76rem" }}>
                  {st.detail}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Registered Plugins */}
      <section className="panel">
        <div className="panel-header">
          <div>
            <h2 className="panel-title">Registered Inspection Plugins</h2>
            <p className="panel-subtitle">
              Ordered ascending by priority. Runtime enablement is controlled through{" "}
              <code>waffynx.yaml</code> and per-site configuration.
            </p>
          </div>
        </div>
        <div className="panel-body">
          {sortedPlugins.length === 0 ? (
            <EmptyState
              icon={<Layers size={22} />}
              title="No plugins registered"
              description="The control plane reported an empty plugin registry."
            />
          ) : (
            <div className="cards-grid">
              {sortedPlugins.map((pl) => (
                <article key={pl.name} className="feature-card">
                  <div className="feature-card-head">
                    <div>
                      <h3 style={{ fontSize: "0.98rem", fontWeight: 700, display: "flex", alignItems: "center", gap: "0.45rem" }}>
                        <Shield size={15} color="var(--accent-primary)" aria-hidden="true" />
                        <span className="mono">{pl.name}</span>
                      </h3>
                      <div className="text-muted mono" style={{ fontSize: "0.73rem", marginTop: 2 }}>
                        v{pl.version} · {pl.author} · {pl.license}
                      </div>
                    </div>
                    <Badge variant="info">Priority {pl.priority}</Badge>
                  </div>

                  <p className="text-secondary" style={{ fontSize: "0.82rem" }}>
                    {pl.description}
                  </p>

                  <div className="feature-card-foot">
                    <div style={{ display: "flex", gap: "0.3rem", flexWrap: "wrap" }}>
                      <Badge variant="ml">{pl.phase}</Badge>
                      {(pl.tags ?? []).map((t) => (
                        <span key={t} className="rule-chip">
                          #{t}
                        </span>
                      ))}
                    </div>
                  </div>
                </article>
              ))}
            </div>
          )}
        </div>
      </section>
    </div>
  );
};
