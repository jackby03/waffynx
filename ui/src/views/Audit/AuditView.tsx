import React, { useCallback, useEffect, useMemo, useState } from "react";
import { Download, FileText, RefreshCw, Search, X } from "lucide-react";
import { wafApi } from "../../api/wafApi";
import { ApiError } from "../../api/client";
import type { AuditEvent } from "../../api/types";
import { KpiCard } from "../../components/common/KpiCard";
import { Badge } from "../../components/common/Badge";
import { EmptyState } from "../../components/common/EmptyState";
import { formatDateTime } from "../../utils/format";
import { downloadCSV, downloadJSON } from "../../utils/exportData";

export const AuditView: React.FC = () => {
  const [entries, setEntries] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [resultFilter, setResultFilter] = useState<"all" | "success" | "allowed" | "blocked">("all");

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const data = await wafApi.getAudit(
        resultFilter !== "all" ? { result: resultFilter } : undefined
      );
      setEntries(data);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not load audit trail.");
    } finally {
      setLoading(false);
    }
  }, [resultFilter]);

  useEffect(() => {
    void load();
  }, [load]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return entries;
    return entries.filter(
      (e) =>
        (e.actor || "").toLowerCase().includes(q) ||
        (e.actor_ip || "").toLowerCase().includes(q) ||
        (e.action || "").toLowerCase().includes(q) ||
        (e.resource || "").toLowerCase().includes(q) ||
        (e.details || "").toLowerCase().includes(q)
    );
  }, [entries, query]);

  const blockedCount = entries.filter((e) => e.result === "blocked").length;
  const distinctActors = new Set(entries.map((e) => e.actor).filter(Boolean)).size;

  const exportCsv = () => {
    downloadCSV("waffynx-audit-log.csv", filtered, [
      { header: "timestamp", value: (e) => e.timestamp },
      { header: "actor", value: (e) => e.actor },
      { header: "actor_ip", value: (e) => e.actor_ip },
      { header: "action", value: (e) => e.action },
      { header: "resource", value: (e) => e.resource },
      { header: "result", value: (e) => e.result },
      { header: "details", value: (e) => e.details ?? "" },
    ]);
  };

  return (
    <div className="canvas-inner">
      <header className="view-header">
        <div>
          <h1 className="view-title" id="view-heading" tabIndex={-1}>
            Governance &amp; Audit Log
          </h1>
          <p className="view-subtitle">
            Control-plane administrative mutations and authenticated API calls from{" "}
            <code>/api/v1/audit</code> (bounded 2,000-entry ring with optional append-only JSONL
            file sink).
          </p>
        </div>
        <div className="view-actions">
          <button type="button" className="btn btn-sm" onClick={() => void load()} disabled={loading}>
            <RefreshCw size={14} aria-hidden="true" />
            <span>Refresh</span>
          </button>
          <button type="button" className="btn btn-sm" disabled={filtered.length === 0} onClick={exportCsv}>
            <Download size={14} aria-hidden="true" />
            <span>CSV</span>
          </button>
          <button
            type="button"
            className="btn btn-sm"
            disabled={filtered.length === 0}
            onClick={() => downloadJSON("waffynx-audit-log.json", filtered)}
          >
            <Download size={14} aria-hidden="true" />
            <span>JSON</span>
          </button>
        </div>
      </header>

      {error && (
        <div className="alert-banner error" role="alert">
          <span>{error}</span>
          <button type="button" className="btn btn-sm" onClick={() => void load()}>
            Retry
          </button>
        </div>
      )}

      <section className="kpi-grid">
        <KpiCard title="Audit Entries" value={entries.length} subtext="Latest 100 matching server query" tone="info" />
        <KpiCard title="Distinct Actors" value={distinctActors} subtext="Operators & API clients" tone="ok" />
        <KpiCard title="Denied / Error Calls" value={blockedCount} subtext="HTTP 4xx / 5xx responses" tone={blockedCount > 0 ? "high" : "default"} />
      </section>

      <section className="panel">
        <div className="filter-bar">
          <div className="filter-row">
            <div className="search-wrap">
              <Search size={15} className="search-wrap-icon" aria-hidden="true" />
              <label htmlFor="audit-search" className="visually-hidden">
                Search audit log
              </label>
              <input
                id="audit-search"
                type="search"
                className="search-input"
                placeholder="Filter by actor, IP, action, resource, or details…"
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

            <div className="pill-group" role="group" aria-label="Filter by audit result">
              {(["all", "success", "allowed", "blocked"] as const).map((res) => (
                <button
                  key={res}
                  type="button"
                  className="pill"
                  aria-pressed={resultFilter === res}
                  onClick={() => setResultFilter(res)}
                >
                  {res === "all" ? "All Results" : res}
                </button>
              ))}
            </div>
          </div>
        </div>

        {loading && entries.length === 0 ? (
          <div className="empty-state">
            <p className="empty-state-desc">Loading audit ledger…</p>
          </div>
        ) : filtered.length === 0 ? (
          <EmptyState
            icon={<FileText size={22} />}
            title="No audit entries match"
            description="Administrative actions (site updates, IP bans, custom rule changes) and API calls appear here."
          />
        ) : (
          <div className="table-scroll" role="region" aria-label="Audit trail table" tabIndex={0}>
            <table className="data-table">
              <caption className="visually-hidden">
                Audit log entries: timestamp, actor, action, resource, result, and details
              </caption>
              <thead>
                <tr>
                  <th scope="col">Timestamp</th>
                  <th scope="col">Actor</th>
                  <th scope="col">Action</th>
                  <th scope="col">Resource</th>
                  <th scope="col">Result</th>
                  <th scope="col">Details</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((ev, idx) => (
                  <tr key={`${ev.timestamp}-${ev.action}-${idx}`}>
                    <td className="mono text-muted">{formatDateTime(ev.timestamp)}</td>
                    <td>
                      <div style={{ fontWeight: 600 }}>{ev.actor || "anonymous"}</div>
                      {ev.actor_ip && (
                        <div className="mono text-muted" style={{ fontSize: "0.72rem" }}>
                          {ev.actor_ip}
                        </div>
                      )}
                    </td>
                    <td>
                      <span className="rule-chip">{ev.action}</span>
                    </td>
                    <td className="mono text-secondary">{ev.resource || "—"}</td>
                    <td>
                      <Badge
                        variant={
                          ev.result === "blocked"
                            ? "critical"
                            : ev.result === "success" || ev.result === "allowed"
                              ? "ok"
                              : "neutral"
                        }
                      >
                        {ev.result || "unknown"}
                      </Badge>
                    </td>
                    <td className="text-secondary cell-truncate" title={ev.details}>
                      {ev.details || "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
};
