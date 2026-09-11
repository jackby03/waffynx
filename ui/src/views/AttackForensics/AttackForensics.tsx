import React, { useState, useMemo } from "react";
import { useWaf } from "../../context/WafContext";
import { Badge } from "../../components/common/Badge";
import { EmptyState } from "../../components/common/EmptyState";
import { ForensicDrawer } from "./ForensicDrawer";
import type { WafEvent } from "../../api/types";
import { IconSearch, IconClose, IconShield } from "../../components/common/Icons";

type VectorFilter = "all" | "sqli" | "xss" | "traversal" | "bot" | "cmdinj" | "ml";

const FILTER_TABS: { id: VectorFilter; label: string }[] = [
  { id: "all", label: "ALL VECTORS" },
  { id: "sqli", label: "SQL INJECTION" },
  { id: "xss", label: "CROSS-SITE SCRIPTING" },
  { id: "traversal", label: "PATH TRAVERSAL" },
  { id: "bot", label: "BOT DEFENSE" },
  { id: "cmdinj", label: "COMMAND INJECTION" },
  { id: "ml", label: "ML ANOMALY" },
];

export const AttackForensics: React.FC = () => {
  const { events, selectedEvent, setSelectedEvent } = useWaf();
  const [filter, setFilter] = useState<VectorFilter>("all");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const pageSize = 12;

  const filteredEvents = useMemo(() => {
    return events.filter((e) => {
      // Category filter
      if (filter !== "all") {
        if (filter === "ml") {
          if (!e.rule_id.includes("appsec") && !e.rule_id.includes("ml")) return false;
        } else if (!e.rule_id.toLowerCase().includes(filter)) {
          return false;
        }
      }
      // Search filter
      if (search.trim()) {
        const q = search.toLowerCase();
        const match =
          e.remote_ip.toLowerCase().includes(q) ||
          e.path.toLowerCase().includes(q) ||
          e.rule_id.toLowerCase().includes(q) ||
          e.matched_value.toLowerCase().includes(q);
        if (!match) return false;
      }
      return true;
    });
  }, [events, filter, search]);

  const totalPages = Math.max(1, Math.ceil(filteredEvents.length / pageSize));
  const currentPageEvents = filteredEvents.slice((page - 1) * pageSize, page * pageSize);

  return (
    <div className="view-container">
      {/* Filter Tabs & Search Bar */}
      <div className="forensics-toolbar">
        <div className="vector-tabs">
          {FILTER_TABS.map((tab) => {
            const count =
              tab.id === "all"
                ? events.length
                : tab.id === "ml"
                ? events.filter((e) => e.rule_id.includes("appsec") || e.rule_id.includes("ml")).length
                : events.filter((e) => e.rule_id.toLowerCase().includes(tab.id)).length;

            return (
              <button
                key={tab.id}
                type="button"
                className={`tab-btn ${filter === tab.id ? "active" : ""}`}
                onClick={() => {
                  setFilter(tab.id);
                  setPage(1);
                }}
              >
                {tab.label}
                <span className="tab-count">{count}</span>
              </button>
            );
          })}
        </div>

        <div className="search-box">
          <span className="search-icon">
            <IconSearch size={15} />
          </span>
          <input
            type="text"
            className="search-input"
            placeholder="Filter by IP, Rule, URI or Payload..."
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(1);
            }}
          />
          {search && (
            <button type="button" className="search-clear" onClick={() => setSearch("")} aria-label="Clear search">
              <IconClose size={13} />
            </button>
          )}
        </div>
      </div>

      {/* Incident Table */}
      <div className="table-card">
        <div className="table-card-header">
          <div>
            <h2 className="table-title">Live Incident Audit & Forensics</h2>
            <span className="table-subtitle">
              Showing {filteredEvents.length} events • Fail-closed enforcement
            </span>
          </div>
          <span className="table-hint">Click any row to open deep forensic analysis</span>
        </div>

        {currentPageEvents.length === 0 ? (
          <EmptyState
            icon={<IconShield size={36} color="var(--text-dim)" />}
            title="No Incidents Match the Filter"
            description="Adjust your vector filter or search query to view intercepted threats."
          />
        ) : (
          <div className="table-responsive">
            <table className="waf-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Rule ID</th>
                  <th>Action</th>
                  <th>Source IP</th>
                  <th>Method</th>
                  <th>Target URI</th>
                  <th>ML Score</th>
                </tr>
              </thead>
              <tbody>
                {currentPageEvents.map((e, idx) => (
                  <tr
                    key={`${e.timestamp}-${idx}`}
                    className="clickable-row"
                    onClick={() => setSelectedEvent(e)}
                  >
                    <td className="cell-time">{new Date(e.timestamp).toLocaleTimeString()}</td>
                    <td className="cell-rule">
                      <span className="rule-tag">{e.rule_id}</span>
                    </td>
                    <td>
                      <Badge variant="critical">DENY</Badge>
                    </td>
                    <td className="cell-ip">{e.remote_ip}</td>
                    <td className="cell-method">
                      <span className={`method-badge method-${e.method.toLowerCase()}`}>
                        {e.method}
                      </span>
                    </td>
                    <td className="cell-path" title={e.path}>
                      {e.path}
                    </td>
                    <td className="cell-score">
                      {e.anomaly_score ? (
                        <span className="score-pill">{(e.anomaly_score * 100).toFixed(0)}%</span>
                      ) : (
                        "--"
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Bar */}
        {totalPages > 1 && (
          <div className="table-pagination">
            <span className="pagination-info">
              Page {page} of {totalPages}
            </span>
            <div className="pagination-controls">
              <button
                type="button"
                className="btn-page"
                disabled={page <= 1}
                onClick={() => setPage((p) => p - 1)}
              >
                Previous
              </button>
              <button
                type="button"
                className="btn-page"
                disabled={page >= totalPages}
                onClick={() => setPage((p) => p + 1)}
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Forensic Drawer */}
      <ForensicDrawer event={selectedEvent} onClose={() => setSelectedEvent(null)} />
    </div>
  );
};
