import React from "react";
import type { WafEvent } from "../../api/types";
import { IconZap, IconArrowRight } from "../common/Icons";

interface ThreatTickerProps {
  events: WafEvent[];
  onSelectEvent: (e: WafEvent) => void;
  onViewAll?: () => void;
}

export const ThreatTicker: React.FC<ThreatTickerProps> = ({
  events,
  onSelectEvent,
  onViewAll,
}) => {
  if (!events || events.length === 0) return null;

  // Display the 3 most recent intercepted threats
  const recentEvents = events.slice(0, 3);

  return (
    <aside className="ticker-strip" aria-label="Live Threat Feed">
      {/* Tactical SOC Threat Stream Header */}
      <div className="ticker-header">
        <span className="ticker-beacon" />
        <span className="ticker-label">
          <IconZap size={14} color="var(--accent-crimson)" />
          <span className="ticker-label-accent">THREAT</span> FEED
        </span>
        <span className="ticker-count-badge" title="Total threats intercepted in session">
          {events.length}
        </span>
      </div>

      {/* Discrete Threat Cards - Full Visibility, Zero Clipping */}
      <div className="ticker-cards-row">
        {recentEvents.map((e, idx) => (
          <button
            key={`${e.timestamp}-${idx}`}
            type="button"
            className="ticker-card"
            onClick={() => onSelectEvent(e)}
            title={`Inspect deep packet forensics for ${e.rule_id} from ${e.remote_ip}`}
          >
            <span className="ticker-card-badge">DROP</span>
            <span className="ticker-card-rule">{e.rule_id}</span>
            <span className="ticker-card-ip">{e.remote_ip}</span>
            <span className="ticker-card-path" title={e.path}>
              {e.path}
            </span>
            <span className="ticker-card-time">
              {new Date(e.timestamp).toLocaleTimeString("en-GB", {
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit",
              })}
            </span>
          </button>
        ))}
      </div>

      {/* View All & Live Stream Indicator */}
      <div className="ticker-actions">
        {onViewAll && (
          <button
            type="button"
            className="ticker-view-all-btn"
            onClick={onViewAll}
            title="Open Attack Forensics to view all intercepted incidents"
          >
            View All ({events.length}) <IconArrowRight size={12} />
          </button>
        )}
        <div className="ticker-live-indicator" title="Connected to Edge SSE Stream">
          <span className="live-dot" />
          <span>LIVE</span>
        </div>
      </div>
    </aside>
  );
};


