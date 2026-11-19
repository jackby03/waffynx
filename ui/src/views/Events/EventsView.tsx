import React, { useEffect, useMemo, useState } from "react";
import { Download, Pause, Play, Search, Shield, Trash2, X } from "lucide-react";
import type { Verdict } from "../../api/types";
import { useWaf } from "../../context/WafContext";
import { Badge } from "../../components/common/Badge";
import { EmptyState } from "../../components/common/EmptyState";
import { KpiCard } from "../../components/common/KpiCard";
import { ACTION_META } from "./EventDetailDialog";
import {
  classifyEventVector,
  eventIdentity,
  formatTime,
  VECTOR_LABELS,
  type AttackVector,
} from "../../utils/format";
import { downloadCSV, downloadJSON } from "../../utils/exportData";

const PAGE_SIZE = 25;
type ActionFilter = "all" | Verdict;
type VectorFilter = "all" | AttackVector;

const VECTOR_TABS: { id: VectorFilter; label: string }[] = [
  { id: "all", label: "All Vectors" },
  { id: "sqli", label: "SQLi" },
  { id: "xss", label: "XSS" },
  { id: "traversal", label: "LFI / Traversal" },
  { id: "rce", label: "RCE / CmdInj" },
  { id: "scanner", label: "Scanners" },
  { id: "log4shell", label: "Log4Shell" },
  { id: "rate_limit", label: "Rate Limit" },
  { id: "ip_ban", label: "IP Bans" },
  { id: "appsec", label: "AppSec ML" },
];

interface EventsViewProps {
  initialQuery?: string;
}

export const EventsView: React.FC<EventsViewProps> = ({ initialQuery = "" }) => {
  const {
    events,
    connected,
    analyticsSource,
    paused,
    bufferedCount,
    loadingInitial,
    loadError,
    togglePaused,
    clearEvents,
    setInspectedEvent,
    refreshAll,
  } = useWaf();

  const [query, setQuery] = useState(initialQuery);
  const [vectorFilter, setVectorFilter] = useState<VectorFilter>("all");
  const [methodFilter, setMethodFilter] = useState("all");
  const [actionFilter, setActionFilter] = useState<ActionFilter>("all");
  const [page, setPage] = useState(1);

  useEffect(() => {
    if (initialQuery) {
      setQuery(initialQuery);
      setPage(1);
    }
  }, [initialQuery]);

  const methods = useMemo(() => {
    const found = new Set<string>();
    for (const ev of events) {
      if (ev.method) found.add(ev.method.toUpperCase());
    }
    return [...found].sort();
  }, [events]);

  const vectorCounts = useMemo(() => {
    const map = new Map<string, number>();
    for (const ev of events) {
      const v = classifyEventVector(ev);
      map.set(v, (map.get(v) ?? 0) + 1);
    }
    return map;
  }, [events]);

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return events.filter((ev) => {
      if (vectorFilter !== "all" && classifyEventVector(ev) !== vectorFilter) return false;
      if (methodFilter !== "all" && (ev.method || "").toUpperCase() !== methodFilter) return false;
      if (actionFilter !== "all" && ev.action !== actionFilter) return false;
      if (!needle) return true;
      return (
        (ev.path || "").toLowerCase().includes(needle) ||
        (ev.remote_ip || "").toLowerCase().includes(needle) ||
        (ev.rule_id || "").toLowerCase().includes(needle) ||
        (ev.reason || "").toLowerCase().includes(needle) ||
        (ev.matched_value || "").toLowerCase().includes(needle)
      );
    });
  }, [events, vectorFilter, methodFilter, actionFilter, query]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const safePage = Math.min(page, totalPages);
  const pageEvents = filtered.slice((safePage - 1) * PAGE_SIZE, safePage * PAGE_SIZE);

  const summary = useMemo(() => {
    let denied = 0;
    let rateLimited = 0;
    const ips = new Set<string>();
    for (const ev of filtered) {
      if (ev.action === "deny") denied += 1;
      if (ev.action === "rate_limited") rateLimited += 1;
      if (ev.remote_ip) ips.add(ev.remote_ip);
    }
    return { denied, rateLimited, ips: ips.size };
  }, [filtered]);

  const exportCsv = () => {
    downloadCSV("waffynx-security-events.csv", filtered, [
      { header: "timestamp", value: (e) => e.timestamp },
      { header: "action", value: (e) => e.action },
      { header: "vector", value: (e) => VECTOR_LABELS[classifyEventVector(e)] },
      { header: "rule_id", value: (e) => e.rule_id },
      { header: "remote_ip", value: (e) => e.remote_ip },
      { header: "method", value: (e) => e.method },
      { header: "path", value: (e) => e.path },
      { header: "reason", value: (e) => e.reason ?? "" },
    ]);
  };

  const hasFilters = Boolean(query || vectorFilter !== "all" || methodFilter !== "all" || actionFilter !== "all");

  return (
    <div className="canvas-inner">
      <header className="view-header">
        <div>
          <h1 className="view-title" id="view-heading" tabIndex={-1}>
            Security Events &amp; Forensics
          </h1>
          <p className="view-subtitle">
            Unified stored ring (up to 1,000 events) merged with the live SSE stream. Click any row
            to inspect normalized payloads and mitigate offending sources.
          </p>
        </div>

        <div className="view-actions">
          <button type="button" className="btn btn-sm" onClick={togglePaused}>
            {paused ? <Play size={14} aria-hidden="true" /> : <Pause size={14} aria-hidden="true" />}
            <span>{paused ? `Resume${bufferedCount ? ` (+${bufferedCount})` : ""}` : "Pause stream"}</span>
          </button>
          <button
            type="button"
            className="btn btn-sm"
            disabled={filtered.length === 0}
            onClick={exportCsv}
          >
            <Download size={14} aria-hidden="true" />
            <span>CSV</span>
          </button>
          <button
            type="button"
            className="btn btn-sm"
            disabled={filtered.length === 0}
            onClick={() => downloadJSON("waffynx-security-events.json", filtered)}
          >
            <Download size={14} aria-hidden="true" />
            <span>JSON</span>
          </button>
          <button
            type="button"
            className="btn btn-sm"
            disabled={events.length === 0}
            onClick={clearEvents}
            title="Clears local view buffer only; stored history on the server is untouched"
          >
            <Trash2 size={14} aria-hidden="true" />
            <span>Clear view</span>
          </button>
        </div>
      </header>

      {loadError && (
        <div className="alert-banner error" role="alert">
          <span>{loadError}</span>
          <button type="button" className="btn btn-sm" onClick={() => void refreshAll()}>
            Retry
          </button>
        </div>
      )}

      <section className="kpi-grid">
        <KpiCard
          title="Matching Events"
          value={filtered.length}
          subtext={`of ${events.length} loaded · Source: ${analyticsSource === "clickhouse" ? "ClickHouse" : "SSE Ring"}`}
          badge={analyticsSource === "clickhouse" ? "ClickHouse" : connected ? "SSE Live" : "Reconnecting"}
          tone="info"
        />
        <KpiCard title="Blocked" value={summary.denied} subtext="HTTP 403 enforced" tone="critical" />
        <KpiCard title="Rate Limited" value={summary.rateLimited} subtext="Throttle threshold tripped" tone="high" />
        <KpiCard title="Distinct Sources" value={summary.ips} subtext="Unique client IPs in view" tone="default" />
      </section>

      <section className="panel" aria-busy={loadingInitial}>
        {/* Composable Filter Bar */}
        <div className="filter-bar">
          <div className="filter-row">
            <div className="search-wrap">
              <Search size={15} className="search-wrap-icon" aria-hidden="true" />
              <label htmlFor="events-search" className="visually-hidden">
                Search security events by IP, path, rule ID, or payload
              </label>
              <input
                id="events-search"
                type="search"
                className="search-input"
                placeholder="Filter by IP, rule ID, path, reason, or payload…"
                value={query}
                onChange={(e) => {
                  setQuery(e.target.value);
                  setPage(1);
                }}
              />
              {query && (
                <button
                  type="button"
                  className="search-clear-btn"
                  onClick={() => {
                    setQuery("");
                    setPage(1);
                  }}
                  aria-label="Clear search query"
                >
                  <X size={13} />
                </button>
              )}
            </div>

            <label htmlFor="events-method" className="visually-hidden">
              Filter by HTTP method
            </label>
            <select
              id="events-method"
              className="select"
              style={{ inlineSize: "auto", minInlineSize: 120 }}
              value={methodFilter}
              onChange={(e) => {
                setMethodFilter(e.target.value);
                setPage(1);
              }}
            >
              <option value="all">Method: All</option>
              {methods.map((m) => (
                <option key={m} value={m}>
                  {m}
                </option>
              ))}
            </select>

            <label htmlFor="events-action" className="visually-hidden">
              Filter by verdict action
            </label>
            <select
              id="events-action"
              className="select"
              style={{ inlineSize: "auto", minInlineSize: 145 }}
              value={actionFilter}
              onChange={(e) => {
                setActionFilter(e.target.value as ActionFilter);
                setPage(1);
              }}
            >
              <option value="all">Verdict: All</option>
              {(Object.keys(ACTION_META) as Verdict[]).map((v) => (
                <option key={v} value={v}>
                  {ACTION_META[v].label}
                </option>
              ))}
            </select>

            {hasFilters && (
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={() => {
                  setQuery("");
                  setVectorFilter("all");
                  setMethodFilter("all");
                  setActionFilter("all");
                  setPage(1);
                }}
              >
                Reset filters
              </button>
            )}
          </div>

          <div className="pill-group" role="group" aria-label="Filter by attack vector">
            {VECTOR_TABS.map((tab) => {
              const count = tab.id === "all" ? events.length : (vectorCounts.get(tab.id) ?? 0);
              return (
                <button
                  key={tab.id}
                  type="button"
                  className="pill"
                  aria-pressed={vectorFilter === tab.id}
                  onClick={() => {
                    setVectorFilter(tab.id);
                    setPage(1);
                  }}
                >
                  <span>{tab.label}</span>
                  <span className="mono text-muted" style={{ fontSize: "0.7rem" }}>
                    {count}
                  </span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Semantic Sticky Table */}
        {pageEvents.length === 0 ? (
          <EmptyState
            icon={<Shield size={22} />}
            title={events.length === 0 ? "No security events recorded" : "No events match current filters"}
            description={
              events.length === 0
                ? "Blocked and rate-limited requests appear here in real time over SSE."
                : "Adjust or clear your search query, attack vector, method, or verdict filters."
            }
          />
        ) : (
          <div className="table-scroll" role="region" aria-label="Security events table" tabIndex={0}>
            <table className="data-table">
              <caption className="visually-hidden">
                Security events: timestamp, verdict, method, target path, source IP, rule ID, and reason
              </caption>
              <thead>
                <tr>
                  <th scope="col">Time</th>
                  <th scope="col">Verdict</th>
                  <th scope="col">Method</th>
                  <th scope="col">Target URI</th>
                  <th scope="col">Source IP</th>
                  <th scope="col">Rule ID</th>
                  <th scope="col">Reason</th>
                </tr>
              </thead>
              <tbody>
                {pageEvents.map((ev) => {
                  const meta = ACTION_META[ev.action];
                  return (
                    <tr
                      key={eventIdentity(ev)}
                      className="row-clickable"
                      onClick={() => setInspectedEvent(ev)}
                    >
                      <td className="mono text-muted">
                        <button
                          type="button"
                          className="btn-link mono"
                          onClick={(e) => {
                            e.stopPropagation();
                            setInspectedEvent(ev);
                          }}
                          aria-label={`Inspect event ${ev.rule_id || "unknown"} at ${formatTime(ev.timestamp)}`}
                        >
                          {formatTime(ev.timestamp)}
                        </button>
                      </td>
                      <td>
                        <Badge variant={meta.variant}>{meta.label}</Badge>
                      </td>
                      <td>
                        <span className={`method-chip ${(ev.method || "").toLowerCase()}`}>
                          {ev.method || "—"}
                        </span>
                      </td>
                      <td className="mono cell-truncate" title={ev.path}>
                        {ev.path || "—"}
                      </td>
                      <td className="mono">{ev.remote_ip || "—"}</td>
                      <td>
                        <span className="rule-chip">{ev.rule_id || "—"}</span>
                      </td>
                      <td className="text-secondary cell-truncate" title={ev.reason}>
                        {ev.reason || "—"}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Footer */}
        <div className="table-footer">
          <span className="mono">
            Showing {filtered.length === 0 ? 0 : (safePage - 1) * PAGE_SIZE + 1}–
            {Math.min(safePage * PAGE_SIZE, filtered.length)} of {filtered.length} events
          </span>
          {totalPages > 1 && (
            <div style={{ display: "flex", alignItems: "center", gap: "0.45rem" }}>
              <button
                type="button"
                className="btn btn-sm"
                disabled={safePage <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
              >
                Previous
              </button>
              <span className="mono">
                Page {safePage} / {totalPages}
              </span>
              <button
                type="button"
                className="btn btn-sm"
                disabled={safePage >= totalPages}
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              >
                Next
              </button>
            </div>
          )}
        </div>
      </section>
    </div>
  );
};
