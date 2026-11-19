import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ApiError } from "../../api/client";
import type { Verdict, WafEvent } from "../../api/types";
import { wafApi } from "../../api/wafApi";
import { Badge } from "../../components/common/Badge";
import { EmptyState } from "../../components/common/EmptyState";
import { KpiCard } from "../../components/common/KpiCard";
import { IconClose, IconSearch, IconShield } from "../../components/common/Icons";
import { ACTION_META, EventDetailDialog } from "./EventDetailDialog";

const HISTORY_LIMIT = 200;

/** The server keeps the last 1000 events; the in-memory list mirrors that bound. */
const MAX_EVENTS = 1000;

type ActionFilter = "all" | Verdict;

/**
 * Identity of a stored event.
 *
 * JSON.stringify keeps the separator out of the key: a path can contain any
 * character, so a hand-built "a|b|c" key can collide.
 */
function eventKey(event: WafEvent): string {
  return JSON.stringify([event.timestamp, event.rule_id, event.path]);
}

/** Keeps the first occurrence of each event, so live arrivals win over history. */
function dedupe(events: WafEvent[]): WafEvent[] {
  const seen = new Set<string>();
  const out: WafEvent[] = [];
  for (const event of events) {
    const key = eventKey(event);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(event);
  }
  return out;
}

const pad = (value: number): string => String(value).padStart(2, "0");

/** HH:MM:SS in the operator's local time; the raw timestamp lives in the dialog. */
function formatTime(timestamp: string): string {
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) return timestamp || "—";
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

const ACTION_FILTERS = Object.keys(ACTION_META) as Verdict[];

export const EventsView: React.FC = () => {
  const [events, setEvents] = useState<WafEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState("");
  const [connected, setConnected] = useState(false);
  const [paused, setPaused] = useState(false);

  const [query, setQuery] = useState("");
  const [methodFilter, setMethodFilter] = useState("all");
  const [actionFilter, setActionFilter] = useState<ActionFilter>("all");

  const [selected, setSelected] = useState<WafEvent | null>(null);

  // The list and its dedupe set are refs as well as state so the stream callback
  // always sees the current window without being resubscribed on every event.
  const eventsRef = useRef<WafEvent[]>([]);
  const seenRef = useRef<Set<string>>(new Set());
  const pausedRef = useRef(false);
  const openerRef = useRef<HTMLElement | null>(null);

  const commit = useCallback((next: WafEvent[]) => {
    eventsRef.current = next;
    setEvents(next);
  }, []);

  const ingest = useCallback(
    (event: WafEvent) => {
      const key = eventKey(event);
      if (seenRef.current.has(key)) return;
      seenRef.current.add(key);

      const next = [event, ...eventsRef.current];
      if (next.length > MAX_EVENTS) {
        // Keep the dedupe set aligned with the visible window instead of letting
        // it grow for the lifetime of the tab.
        for (const dropped of next.splice(MAX_EVENTS)) seenRef.current.delete(eventKey(dropped));
      }
      commit(next);
    },
    [commit]
  );

  const loadHistory = useCallback(async () => {
    setLoading(true);
    setLoadError("");
    try {
      const history = await wafApi.getEventHistory(HISTORY_LIMIT);
      // Live frames can land while the request is in flight and are newer than
      // the snapshot, so they keep their place at the top of the list.
      const merged = dedupe([...eventsRef.current, ...history]).slice(0, MAX_EVENTS);
      seenRef.current = new Set(merged.map(eventKey));
      commit(merged);
    } catch (err) {
      setLoadError(
        err instanceof ApiError
          ? err.message
          : err instanceof Error
            ? err.message
            : "Could not load the event history."
      );
    } finally {
      setLoading(false);
    }
  }, [commit]);

  useEffect(() => {
    void loadHistory();
  }, [loadHistory]);

  useEffect(() => {
    // Subscribed once: pausing must not tear down the connection, so the callback
    // reads the pause flag from a ref.
    const unsubscribe = wafApi.subscribeEvents(
      (event) => {
        if (!pausedRef.current) ingest(event);
      },
      setConnected,
      undefined,
      // The shell owns the 401 redirect; here it only means the feed is gone.
      () => setConnected(false)
    );
    return unsubscribe;
  }, [ingest]);

  const methods = useMemo(() => {
    const found = new Set<string>();
    for (const event of events) {
      if (event.method) found.add(event.method.toUpperCase());
    }
    return [...found].sort();
  }, [events]);

  // A reset or a fresh history can drop the selected method; a filter that can no
  // longer match anything would look like an empty history.
  useEffect(() => {
    if (methodFilter !== "all" && !methods.includes(methodFilter)) setMethodFilter("all");
  }, [methodFilter, methods]);

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return events.filter((event) => {
      if (methodFilter !== "all" && event.method.toUpperCase() !== methodFilter) return false;
      if (actionFilter !== "all" && event.action !== actionFilter) return false;
      if (!needle) return true;
      return (
        event.path.toLowerCase().includes(needle) ||
        event.remote_ip.toLowerCase().includes(needle) ||
        event.rule_id.toLowerCase().includes(needle)
      );
    });
  }, [events, methodFilter, actionFilter, query]);

  const summary = useMemo(() => {
    let denied = 0;
    let rateLimited = 0;
    const ips = new Set<string>();
    for (const event of events) {
      if (event.action === "deny") denied += 1;
      if (event.action === "rate_limited") rateLimited += 1;
      if (event.remote_ip) ips.add(event.remote_ip);
    }
    return { denied, rateLimited, ips: ips.size };
  }, [events]);

  const togglePaused = () => {
    pausedRef.current = !pausedRef.current;
    setPaused(pausedRef.current);
  };

  const resetList = () => {
    // Local only: the stored history in the control plane is untouched.
    seenRef.current = new Set();
    commit([]);
  };

  const openDetail = (event: WafEvent, opener: HTMLElement | null) => {
    openerRef.current = opener;
    setSelected(event);
  };

  const closeDetail = () => {
    setSelected(null);
    const opener = openerRef.current;
    openerRef.current = null;
    // The panel is unmounted after closing, so give focus back to the row that
    // opened it rather than relying on the browser's dialog heuristic.
    if (opener) opener.focus();
  };

  return (
    <section className="view-container" aria-labelledby="events-title">
      {/* The topbar already prints the page title, so this header carries only
          the state controls; repeating the heading made every screen show it twice. */}
      <header className="view-header">
        <p className="view-subtitle" id="events-title">
          Stored by the control plane, plus the live stream. The engine publishes one event for
          each verdict it applies to inspected traffic.
        </p>

        <div className="topbar-actions">
          <span className="connection-pill" role="status">
            <span
              className={`conn-dot ${connected ? "connected" : "reconnecting"}`}
              aria-hidden="true"
            />
            {connected ? "Live" : "Disconnected"}
          </span>
          {paused && <Badge variant="high">Ingesta en pausa</Badge>}
          <button type="button" className="btn-secondary" onClick={togglePaused}>
            {paused ? "Resume ingest" : "Pause ingest"}
          </button>
          <button
            type="button"
            className="btn-secondary"
            onClick={resetList}
            disabled={events.length === 0}
            title="Clears the in-memory list only; nothing is deleted on the server"
          >
            Clear list
          </button>
        </div>
      </header>

      <div className="kpi-grid">
        <KpiCard
          title="Loaded events"
          value={events.length}
          subtext="In memory"
          variant="info"
        />
        <KpiCard
          title="Denied"
          value={summary.denied}
          subtext="verdict deny"
          variant="critical"
        />
        <KpiCard
          title="Rate limited"
          value={summary.rateLimited}
          subtext="verdict rate_limited"
          variant="warning"
        />
        <KpiCard
          title="Source IPs"
          value={summary.ips}
          subtext="Distinct in window"
          variant="default"
        />
      </div>

      <div className="forensics-toolbar">
        <div className="search-box">
          <span className="search-icon" aria-hidden="true">
            <IconSearch size={15} />
          </span>
          <label className="sr-only" htmlFor="events-search">
            Search events by path, IP or rule
          </label>
          <input
            id="events-search"
            type="search"
            className="search-input"
            placeholder="Filter by path, IP or rule…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          {query && (
            <button
              type="button"
              className="search-clear"
              onClick={() => setQuery("")}
              aria-label="Clear filter"
            >
              <IconClose size={13} />
            </button>
          )}
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", flexWrap: "wrap" }}>
          <label className="form-label" htmlFor="events-method">
            Method
          </label>
          <select
            id="events-method"
            className="algo-select"
            value={methodFilter}
            onChange={(e) => setMethodFilter(e.target.value)}
          >
            <option value="all">All</option>
            {methods.map((method) => (
              <option key={method} value={method}>
                {method}
              </option>
            ))}
          </select>

          <label className="form-label" htmlFor="events-action">
            Action
          </label>
          <select
            id="events-action"
            className="algo-select"
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value as ActionFilter)}
          >
            <option value="all">All</option>
            {ACTION_FILTERS.map((verdict) => (
              <option key={verdict} value={verdict}>
                {ACTION_META[verdict].label}
              </option>
            ))}
          </select>
        </div>
      </div>

      {loadError && (
        <div
          className="alert alert-error"
          role="alert"
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: "1rem",
            flexWrap: "wrap",
          }}
        >
          <span>{loadError}</span>
          <button type="button" className="btn-secondary" onClick={() => void loadHistory()}>
            Reintentar
          </button>
        </div>
      )}

      <div className="table-card" aria-busy={loading}>
        <div className="table-card-header">
          <div>
            <h2 className="table-title">Event history</h2>
            <span className="table-subtitle" aria-live="polite">
              {filtered.length} of {events.length} events
            </span>
          </div>
          <span className="table-hint">Select a row or its time to open the detail</span>
        </div>

        {loading && events.length === 0 ? (
          <p className="table-hint" role="status">
            Loading history…
          </p>
        ) : loadError && events.length === 0 ? (
          // A failed load is not an empty history: say so instead of claiming
          // there are no events.
          <p className="table-hint" role="status">
            The history is unavailable. Use "Retry" to try again.
          </p>
        ) : filtered.length === 0 ? (
          <EmptyState
            icon={<IconShield size={32} />}
            title={events.length === 0 ? "No events yet" : "No event matches"}
            description={
              events.length === 0
                ? "The API keeps the last 1000 events it has seen. An empty list means it has not recorded any yet."
                : "Adjust the search, the method or the action to see other events."
            }
          />
        ) : (
          <div
            className="table-scroll"
            role="region"
            aria-label="Stored event history"
            tabIndex={0}
          >
            <table className="waf-table">
              <caption className="sr-only">
                {filtered.length} of {events.length} security events: time, method, path, source IP,
                de origen, regla y motivo
              </caption>
              <thead>
                <tr>
                  <th scope="col">Time</th>
                  <th scope="col">Method</th>
                  <th scope="col">Path</th>
                  <th scope="col">Source IP</th>
                  <th scope="col">Rule</th>
                  <th scope="col">Reason</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((event) => (
                  <tr
                    key={eventKey(event)}
                    className="clickable-row"
                    onClick={(e) =>
                      openDetail(event, e.currentTarget.querySelector<HTMLButtonElement>("button"))
                    }
                  >
                    <td className="cell-time">
                      <button
                        type="button"
                        className="btn-link"
                        style={{
                          color: "var(--text-dim)",
                          textDecoration: "none",
                          fontFamily: "var(--font-mono)",
                        }}
                        onClick={(e) => {
                          e.stopPropagation();
                          openDetail(event, e.currentTarget);
                        }}
                        aria-label={`Abrir detalle del evento ${event.rule_id || "sin regla"} de las ${formatTime(event.timestamp)}`}
                      >
                        {formatTime(event.timestamp)}
                      </button>
                    </td>
                    <td>
                      <span className={`method-badge method-${event.method.toLowerCase()}`}>
                        {event.method || "—"}
                      </span>
                    </td>
                    <td className="cell-path" title={event.path}>
                      {event.path || "—"}
                    </td>
                    <td className="cell-ip">{event.remote_ip || "—"}</td>
                    <td className="cell-rule">
                      {event.rule_id ? (
                        <span className="rule-tag">{event.rule_id}</span>
                      ) : (
                        "—"
                      )}
                    </td>
                    <td className="cell-reason">{event.reason || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <EventDetailDialog event={selected} onClose={closeDetail} />
    </section>
  );
};
