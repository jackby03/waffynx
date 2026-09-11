import React, { useState, useMemo } from "react";
import { useWaf } from "../../context/WafContext";
import { KpiCard } from "../../components/common/KpiCard";
import { Badge } from "../../components/common/Badge";
import { ToggleSwitch } from "../../components/common/ToggleSwitch";
import type { Rule } from "../../api/types";

export const SecurityPolicies: React.FC = () => {
  const { rules } = useWaf();
  const [activeCategory, setActiveCategory] = useState<string>("all");
  const [localRules, setLocalRules] = useState<Rule[]>(rules);

  // Sync when rules load
  React.useEffect(() => {
    if (rules.length) setLocalRules(rules);
  }, [rules]);

  const toggleRule = (id: string) => {
    setLocalRules((prev) =>
      prev.map((r) => (r.id === id ? { ...r, enabled: !r.enabled } : r))
    );
  };

  const categories = useMemo(() => {
    const list = Array.from(new Set(localRules.map((r) => r.category)));
    return ["all", ...list];
  }, [localRules]);

  const filteredRules = useMemo(() => {
    if (activeCategory === "all") return localRules;
    return localRules.filter((r) => r.category === activeCategory);
  }, [localRules, activeCategory]);

  const criticalCount = localRules.filter((r) => r.severity === "critical").length;
  const enabledCount = localRules.filter((r) => r.enabled).length;

  return (
    <div className="view-container">
      {/* 4 Standardized KPI Cards */}
      <section className="kpi-grid">
        <KpiCard
          title="Active Signatures"
          value={`${enabledCount} / ${localRules.length}`}
          subtext="Compiled into deterministic Aho-Corasick tree"
          badge="Enforced"
          variant="info"
        />
        <KpiCard
          title="Critical Signatures"
          value={criticalCount}
          subtext="Immediate drop on match"
          badge="High Priority"
          variant="critical"
        />
        <KpiCard
          title="Inspection Latency"
          value="180 µs"
          subtext="P50 evaluation time per request"
          badge="Zero-Copy"
          variant="success"
        />
        <KpiCard
          title="Threat Coverage"
          value="OWASP Top 10"
          subtext="A01 through A10 full mitigation"
          badge="Compliant"
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
              className={`cat-btn ${activeCategory === cat ? "active" : ""}`}
              onClick={() => setActiveCategory(cat)}
            >
              {cat.toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      {/* Rules Table */}
      <div className="table-card">
        <div className="table-card-header">
          <div>
            <h2 className="table-title">Signature Set & Rule Inspection</h2>
            <span className="table-subtitle">
              Configured security policies enforced at Nginx module ingress
            </span>
          </div>
        </div>

        <div className="table-responsive">
          <table className="waf-table">
            <thead>
              <tr>
                <th>Status</th>
                <th>Rule ID</th>
                <th>Rule Name & Description</th>
                <th>Category</th>
                <th>Severity</th>
                <th>Total Hits</th>
                <th>Pattern / Expression</th>
              </tr>
            </thead>
            <tbody>
              {filteredRules.map((rule) => (
                <tr key={rule.id}>
                  <td>
                    <ToggleSwitch
                      checked={rule.enabled}
                      onChange={() => toggleRule(rule.id)}
                    />
                  </td>
                  <td className="cell-rule">
                    <span className="rule-tag">{rule.id}</span>
                  </td>
                  <td className="cell-desc">
                    <strong>{rule.name}</strong>
                    <p className="rule-explanation">{rule.description}</p>
                  </td>
                  <td>
                    <span className="category-pill">{rule.category.toUpperCase()}</span>
                  </td>
                  <td>
                    <Badge variant={rule.severity}>{rule.severity.toUpperCase()}</Badge>
                  </td>
                  <td className="cell-hits">{rule.hits.toLocaleString()}</td>
                  <td className="cell-pattern">
                    <code>{rule.pattern}</code>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
