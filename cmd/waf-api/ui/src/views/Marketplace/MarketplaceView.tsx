import React, { useState, useMemo } from "react";
import { useWaf } from "../../context/WafContext";
import { KpiCard } from "../../components/common/KpiCard";
import { ToggleSwitch } from "../../components/common/ToggleSwitch";
import { Badge } from "../../components/common/Badge";

export const MarketplaceView: React.FC = () => {
  const { plugins, togglePlugin } = useWaf();
  const [selectedCat, setSelectedCat] = useState<string>("all");

  const categories = ["all", "detection", "mitigation", "ml", "core"];

  const filteredPlugins = useMemo(() => {
    if (selectedCat === "all") return plugins;
    return plugins.filter((p) => p.category === selectedCat);
  }, [plugins, selectedCat]);

  const activeCount = plugins.filter((p) => p.enabled).length;

  return (
    <div className="view-container">
      {/* 4 Standardized KPI Cards */}
      <section className="kpi-grid">
        <KpiCard
          title="Active Plugins"
          value={`${activeCount} / ${plugins.length}`}
          subtext="Executing on every HTTP request"
          badge="Live Chain"
          variant="info"
        />
        <KpiCard
          title="Plugin Protocol"
          value="Go / C++"
          subtext="Shared memory zero-copy inter-process communication"
          badge="Fast IPC"
          variant="success"
        />
        <KpiCard
          title="Pipeline Priority"
          value="10 → 60"
          subtext="Ordered deterministic execution order"
          badge="Aho-Corasick"
          variant="default"
        />
        <KpiCard
          title="Security Sandboxing"
          value="POSIX Jailed"
          subtext="Isolated memory limits and read-only root"
          badge="Hardened"
          variant="default"
        />
      </section>

      {/* Category Tabs */}
      <div className="category-toolbar">
        <div className="category-tabs">
          {categories.map((cat) => (
            <button
              key={cat}
              type="button"
              className={`cat-btn ${selectedCat === cat ? "active" : ""}`}
              onClick={() => setSelectedCat(cat)}
            >
              {cat.toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      {/* Plugins Grid */}
      <div className="plugins-grid">
        {filteredPlugins.map((plugin) => (
          <div key={plugin.id} className={`plugin-card ${plugin.enabled ? "enabled" : ""}`}>
            <div className="plugin-header">
              <div className="plugin-title-group">
                <h3 className="plugin-name">{plugin.name}</h3>
                <span className="plugin-version">v{plugin.version} • {plugin.author}</span>
              </div>
              <ToggleSwitch
                checked={plugin.enabled}
                onChange={(checked) => togglePlugin(plugin.id, checked)}
                disabled={!plugin.installed}
              />
            </div>

            <p className="plugin-desc">{plugin.description}</p>

            <div className="plugin-meta">
              <div className="plugin-tags">
                {plugin.tags.map((t) => (
                  <span key={t} className="tag-chip">
                    #{t}
                  </span>
                ))}
              </div>
              <div className="plugin-status-badge">
                <Badge variant={plugin.enabled ? "success" : "neutral"}>
                  {plugin.enabled ? "ACTIVE (PRIORITY " + plugin.priority + ")" : "DISABLED"}
                </Badge>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
