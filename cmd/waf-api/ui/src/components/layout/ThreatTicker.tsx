import React from "react";
import type { WafEvent } from "../../api/types";

interface ThreatTickerProps {
  events: WafEvent[];
  onSelectEvent: (e: WafEvent) => void;
}

export const ThreatTicker: React.FC<ThreatTickerProps> = ({ events, onSelectEvent }) => {
  if (!events.length) return null;

  const topRecent = events.slice(0, 4);

  return (
    <aside className="ticker-strip" aria-label="Live Threat Feed">
      <span className="ticker-label">⚡ THREAT FEED</span>
      <div className="ticker-items">
        {topRecent.map((e, idx) => (
          <button
            key={`${e.timestamp}-${idx}`}
            type="button"
            className="ticker-item"
            onClick={() => onSelectEvent(e)}
          >
            <span className="ticker-time">{new Date(e.timestamp).toLocaleTimeString()}</span>
            <span className="ticker-rule">{e.rule_id}</span>
            <span className="ticker-ip">{e.remote_ip}</span>
            <span className="ticker-path">{e.path.slice(0, 32)}{e.path.length > 32 ? "…" : ""}</span>
          </button>
        ))}
      </div>
    </aside>
  );
};
