import React, { useMemo, useState } from "react";
import { useWaf } from "../../context/WafContext";
import { KpiCard } from "../../components/common/KpiCard";
import { Badge } from "../../components/common/Badge";

// SecurityPolicies renders the managed ruleset exactly as /api/v1/rules reports it.
//
// It is deliberately read-only: the catalog is compiled into the binary at startup
// and cannot be toggled per rule at runtime. The previous version showed enable
// switches and hit counters that did not exist on the server, which is worse than
// useless: it looks like control the operator does not have.
export const SecurityPolicies: React.FC = () => {
  const { rules } = useWaf();
  const [activeTag, setActiveTag] = useState<string>("all");
  const [query, setQuery] = useState("");

  const tags = useMemo(() => {
    const set = new Set<string>();
    for (const rule of rules) {
      for (const tag of rule.tags ?? []) set.add(tag);
    }
    return ["all", ...[...set].sort()];
  }, [rules]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return rules.filter((rule) => {
      const matchesTag = activeTag === "all" || (rule.tags ?? []).includes(activeTag);
      if (!matchesTag) return false;
      if (!q) return true;
      return (
        rule.id.toLowerCase().includes(q) ||
        rule.name.toLowerCase().includes(q)
      );
    });
  }, [rules, activeTag, query]);

  const critical = rules.filter((r) => r.severity === "critical").length;
  const high = rules.filter((r) => r.severity === "high").length;
  const logging = rules.filter((r) => r.action === "log").length;

  return (
    <div className="view-stack">
      <header className="view-header">
        <div>
          <h1 className="view-title">Security Policies</h1>
          <p className="view-subtitle">
            The managed ruleset compiled into this build. It is read-only here: rule ids,
            severities and actions come from the catalog, and changing them means shipping a new
            catalog, not flipping a switch.
          </p>
        </div>
      </header>

      <section className="kpi-grid">
        <KpiCard
          title="Managed signatures"
          value={rules.length}
          subtext="One Aho–Corasick pass per field"
          badge="Deterministic"
          variant="info"
        />
        <KpiCard
          title="Critical"
          value={critical}
          subtext="Blocked before any other stage"
          badge="Immediate drop"
          variant="critical"
        />
        <KpiCard
          title="High"
          value={high}
          subtext="Blocked, lower confidence than critical"
          badge="Enforced"
          variant="warning"
        />
        <KpiCard
          title="Log only"
          value={logging}
          subtext="Recorded but never blocked"
          badge="Advisory"
          variant="success"
        />
      </section>

      <div className="table-card">
        <div className="table-card-header">
          <div>
            <h2 className="table-title">Rule matrix</h2>
            <span className="table-subtitle">
              {filtered.length} of {rules.length} rules
            </span>
          </div>
          <label className="form-label sr-only" htmlFor="rule-search">
            Filter rules
          </label>
          <input
            id="rule-search"
            type="search"
            className="form-input search-input"
            placeholder="Filter by id or name"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>

        <div className="pill-row" role="group" aria-label="Filter by tag">
          {tags.map((tag) => (
            <button
              key={tag}
              type="button"
              className={`pill ${activeTag === tag ? "pill-active" : ""}`}
              aria-pressed={activeTag === tag}
              onClick={() => setActiveTag(tag)}
            >
              {tag}
            </button>
          ))}
        </div>

        {rules.length === 0 ? (
          <p className="table-hint" role="status">
            The ruleset could not be loaded. The API returns 503 when the embedded catalog is
            invalid, rather than an empty list that would look like “nothing to enforce”.
          </p>
        ) : filtered.length === 0 ? (
          <p className="table-hint" role="status">
            No rule matches that filter.
          </p>
        ) : (
          <div className="table-scroll" role="region" aria-label="Managed rules" tabIndex={0}>
            <table className="waf-table">
              <caption className="sr-only">
                Managed rules: identifier, name, severity, action, tags and inspected fields
              </caption>
              <thead>
                <tr>
                  <th scope="col">Rule</th>
                  <th scope="col">Name</th>
                  <th scope="col">Severity</th>
                  <th scope="col">Action</th>
                  <th scope="col">Tags</th>
                  <th scope="col">Fields</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((rule) => (
                  <tr key={rule.id}>
                    <td>
                      <code>{rule.id}</code>
                    </td>
                    <td>{rule.name}</td>
                    <td>
                      <Badge variant={rule.severity}>{rule.severity.toUpperCase()}</Badge>
                    </td>
                    <td>
                      <span className={rule.action === "block" ? "text-danger" : "text-muted"}>
                        {rule.action}
                      </span>
                    </td>
                    <td>{(rule.tags ?? []).join(", ")}</td>
                    <td className="text-muted">{(rule.fields ?? []).join(", ")}</td>
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
