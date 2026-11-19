import React, { useEffect, useMemo, useState } from "react";
import { Lock, Search, ShieldCheck, X } from "lucide-react";
import { useWaf } from "../../context/WafContext";
import type { ManagedRule, Severity } from "../../api/types";
import { KpiCard } from "../../components/common/KpiCard";
import { Badge } from "../../components/common/Badge";
import { EmptyState } from "../../components/common/EmptyState";
import { Dialog } from "../../components/common/Dialog";
import { formatTime } from "../../utils/format";

interface SecurityPoliciesProps {
  initialQuery?: string;
}

export const SecurityPolicies: React.FC<SecurityPoliciesProps> = ({ initialQuery = "" }) => {
  const { rules, events, setInspectedEvent } = useWaf();
  const [activeTag, setActiveTag] = useState("all");
  const [severityFilter, setSeverityFilter] = useState<"all" | Severity>("all");
  const [actionFilter, setActionFilter] = useState<"all" | "block" | "log">("all");
  const [fieldFilter, setFieldFilter] = useState("all");
  const [query, setQuery] = useState(initialQuery);
  const [selectedRule, setSelectedRule] = useState<ManagedRule | null>(null);

  useEffect(() => {
    if (initialQuery) setQuery(initialQuery);
  }, [initialQuery]);

  const tags = useMemo(() => {
    const set = new Set<string>();
    for (const rule of rules) {
      for (const tag of rule.tags ?? []) set.add(tag);
    }
    return ["all", ...[...set].sort()];
  }, [rules]);

  const fields = useMemo(() => {
    const set = new Set<string>();
    for (const rule of rules) {
      for (const f of rule.fields ?? []) set.add(f);
    }
    return [...set].sort();
  }, [rules]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return rules.filter((rule) => {
      if (activeTag !== "all" && !(rule.tags ?? []).includes(activeTag)) return false;
      if (severityFilter !== "all" && rule.severity !== severityFilter) return false;
      if (actionFilter !== "all" && rule.action !== actionFilter) return false;
      if (fieldFilter !== "all" && !(rule.fields ?? []).includes(fieldFilter)) return false;
      if (!q) return true;
      return (
        rule.id.toLowerCase().includes(q) ||
        rule.name.toLowerCase().includes(q) ||
        (rule.tags ?? []).some((t) => t.toLowerCase().includes(q))
      );
    });
  }, [rules, activeTag, severityFilter, actionFilter, fieldFilter, query]);

  const criticalCount = rules.filter((r) => r.severity === "critical").length;
  const highCount = rules.filter((r) => r.severity === "high").length;
  const logCount = rules.filter((r) => r.action === "log").length;

  const matchingEventsForSelected = useMemo(() => {
    if (!selectedRule) return [];
    return events.filter((e) => e.rule_id === selectedRule.id).slice(0, 12);
  }, [selectedRule, events]);

  return (
    <div className="canvas-inner">
      <header className="view-header">
        <div>
          <h1 className="view-title" id="view-heading" tabIndex={-1}>
            Managed Ruleset Catalog
          </h1>
          <p className="view-subtitle">
            Declarative signatures compiled into a single Aho-Corasick automaton at startup. This
            catalog is strictly read-only at runtime; use Custom Rules for dynamic policies.
          </p>
        </div>
        <Badge variant="neutral">
          <Lock size={12} aria-hidden="true" />
          Read-Only Compiled Catalog
        </Badge>
      </header>

      <section className="kpi-grid">
        <KpiCard
          title="Managed Signatures"
          value={rules.length}
          subtext="Single-pass Aho-Corasick matcher"
          badge="Deterministic"
          tone="info"
        />
        <KpiCard
          title="Critical"
          value={criticalCount}
          subtext="Immediate drop before plugins"
          badge="High confidence"
          tone="critical"
        />
        <KpiCard
          title="High Severity"
          value={highCount}
          subtext="Enforced attack signatures"
          badge="Enforced"
          tone="high"
        />
        <KpiCard
          title="Log Only"
          value={logCount}
          subtext="Advisory signals; never drop"
          badge="Observation"
          tone="ok"
        />
      </section>

      <section className="panel">
        <div className="filter-bar">
          <div className="filter-row">
            <div className="search-wrap">
              <Search size={15} className="search-wrap-icon" aria-hidden="true" />
              <label htmlFor="managed-rules-search" className="visually-hidden">
                Filter managed rules by ID, name, or tag
              </label>
              <input
                id="managed-rules-search"
                type="search"
                className="search-input"
                placeholder="Filter by rule ID (e.g., WAF-SQLI-001), name, or tag…"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
              />
              {query && (
                <button
                  type="button"
                  className="search-clear-btn"
                  onClick={() => setQuery("")}
                  aria-label="Clear search"
                >
                  <X size={13} />
                </button>
              )}
            </div>

            <label htmlFor="rules-severity" className="visually-hidden">
              Filter by severity
            </label>
            <select
              id="rules-severity"
              className="select"
              style={{ inlineSize: "auto", minInlineSize: 138 }}
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value as "all" | Severity)}
            >
              <option value="all">Severity: All</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>

            <label htmlFor="rules-action" className="visually-hidden">
              Filter by action
            </label>
            <select
              id="rules-action"
              className="select"
              style={{ inlineSize: "auto", minInlineSize: 125 }}
              value={actionFilter}
              onChange={(e) => setActionFilter(e.target.value as "all" | "block" | "log")}
            >
              <option value="all">Action: All</option>
              <option value="block">Block</option>
              <option value="log">Log</option>
            </select>

            <label htmlFor="rules-field" className="visually-hidden">
              Filter by inspected field
            </label>
            <select
              id="rules-field"
              className="select"
              style={{ inlineSize: "auto", minInlineSize: 140 }}
              value={fieldFilter}
              onChange={(e) => setFieldFilter(e.target.value)}
            >
              <option value="all">Field: All</option>
              {fields.map((f) => (
                <option key={f} value={f}>
                  {f}
                </option>
              ))}
            </select>
          </div>

          <div className="pill-group" role="group" aria-label="Filter by rule category tag">
            {tags.map((tag) => (
              <button
                key={tag}
                type="button"
                className="pill"
                aria-pressed={activeTag === tag}
                onClick={() => setActiveTag(tag)}
              >
                {tag}
              </button>
            ))}
          </div>
        </div>

        {rules.length === 0 ? (
          <EmptyState
            icon={<ShieldCheck size={22} />}
            title="Managed ruleset unavailable"
            description="The API returns 503 when the embedded catalog fails validation rather than silently pretending zero rules are active."
          />
        ) : filtered.length === 0 ? (
          <EmptyState
            icon={<ShieldCheck size={22} />}
            title="No signatures match current filters"
            description="Reset one or more filters to browse the full compiled ruleset."
          />
        ) : (
          <div className="table-scroll" role="region" aria-label="Managed rules matrix" tabIndex={0}>
            <table className="data-table">
              <caption className="visually-hidden">
                Managed ruleset: rule ID, name, severity, action, tags, and inspected fields
              </caption>
              <thead>
                <tr>
                  <th scope="col">Rule ID</th>
                  <th scope="col">Signature Name</th>
                  <th scope="col">Severity</th>
                  <th scope="col">Action</th>
                  <th scope="col">Tags</th>
                  <th scope="col">Inspected Fields</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((rule) => (
                  <tr
                    key={rule.id}
                    className="row-clickable"
                    onClick={() => setSelectedRule(rule)}
                  >
                    <td>
                      <button
                        type="button"
                        className="btn-link mono"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedRule(rule);
                        }}
                      >
                        {rule.id}
                      </button>
                    </td>
                    <td style={{ fontWeight: 550 }}>{rule.name}</td>
                    <td>
                      <Badge variant={rule.severity}>{rule.severity.toUpperCase()}</Badge>
                    </td>
                    <td>
                      <Badge variant={rule.action === "block" ? "critical" : "neutral"}>
                        {rule.action.toUpperCase()}
                      </Badge>
                    </td>
                    <td>
                      <div style={{ display: "flex", gap: "0.3rem", flexWrap: "wrap" }}>
                        {(rule.tags ?? []).map((t) => (
                          <span key={t} className="rule-chip">
                            {t}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="mono text-secondary">{(rule.fields ?? []).join(", ")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <div className="table-footer">
          <span className="mono">
            Showing {filtered.length} of {rules.length} compiled signatures
          </span>
          <span>Click any rule to inspect normalization coverage and recent matches</span>
        </div>
      </section>

      {/* Rule Detail Drawer */}
      <Dialog
        open={Boolean(selectedRule)}
        onClose={() => setSelectedRule(null)}
        eyebrow="Managed Signature Details"
        title={selectedRule?.id ?? "Rule"}
        variant="drawer"
        footer={
          <button type="button" className="btn" onClick={() => setSelectedRule(null)}>
            Close
          </button>
        }
      >
        {selectedRule && (
          <>
            <dl className="detail-grid">
              <div className="detail-cell wide">
                <dt>Signature Name</dt>
                <dd style={{ fontWeight: 700 }}>{selectedRule.name}</dd>
              </div>
              <div className="detail-cell">
                <dt>Severity</dt>
                <dd>
                  <Badge variant={selectedRule.severity}>{selectedRule.severity.toUpperCase()}</Badge>
                </dd>
              </div>
              <div className="detail-cell">
                <dt>Enforcement Action</dt>
                <dd>
                  <Badge variant={selectedRule.action === "block" ? "critical" : "neutral"}>
                    {selectedRule.action.toUpperCase()}
                  </Badge>
                </dd>
              </div>
              <div className="detail-cell wide">
                <dt>Inspected Fields</dt>
                <dd className="mono">{(selectedRule.fields ?? []).join(", ")}</dd>
              </div>
              <div className="detail-cell wide">
                <dt>Tags</dt>
                <dd>{(selectedRule.tags ?? []).join(", ") || "—"}</dd>
              </div>
            </dl>

            <div className="alert-banner info">
              Requests pass through percent-decoding, HTML &amp; JSON escape decoding, lowercasing,
              and whitespace/SQL-comment squashing before matching this signature.
            </div>

            <div>
              <h3 className="panel-title" style={{ marginBottom: "0.5rem" }}>
                Recent Matches in Event Ring ({matchingEventsForSelected.length})
              </h3>
              {matchingEventsForSelected.length === 0 ? (
                <p className="text-secondary" style={{ fontSize: "0.82rem" }}>
                  No events in the current control-plane ring matched <code>{selectedRule.id}</code>.
                </p>
              ) : (
                <div className="table-scroll" role="region" aria-label="Matching rule events" tabIndex={0}>
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th scope="col">Time</th>
                        <th scope="col">Source IP</th>
                        <th scope="col">Path</th>
                      </tr>
                    </thead>
                    <tbody>
                      {matchingEventsForSelected.map((ev, i) => (
                        <tr
                          key={`${ev.timestamp}-${i}`}
                          className="row-clickable"
                          onClick={() => {
                            setSelectedRule(null);
                            setInspectedEvent(ev);
                          }}
                        >
                          <td className="mono text-muted">{formatTime(ev.timestamp)}</td>
                          <td className="mono">{ev.remote_ip}</td>
                          <td className="mono cell-truncate">{ev.path}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </>
        )}
      </Dialog>
    </div>
  );
};
