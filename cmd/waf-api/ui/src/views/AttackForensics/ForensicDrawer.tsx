import React, { useState } from "react";
import type { WafEvent } from "../../api/types";
import { Badge } from "../../components/common/Badge";
import { useWaf } from "../../context/WafContext";

interface ForensicDrawerProps {
  event: WafEvent | null;
  onClose: () => void;
}

/** Highlights attack indicators in red */
function highlightPayload(text: string): React.ReactNode {
  if (!text) return "None";

  // Regex patterns to highlight
  const hostileRegex =
    /(UNION\s+SELECT|SELECT\s+|FROM\s+|OR\s+'1'='1|--|<script[^>]*>|<\/script>|onerror=|onload=|\.\.\/|\.\.\\|\/etc\/passwd|whoami|cat\s+|sqlmap|Nikto)/gi;

  const parts = text.split(hostileRegex);
  return parts.map((part, i) => {
    if (part.match(hostileRegex)) {
      return (
        <mark key={i} className="payload-highlight">
          {part}
        </mark>
      );
    }
    return part;
  });
}

export const ForensicDrawer: React.FC<ForensicDrawerProps> = ({ event, onClose }) => {
  const { unbanIP } = useWaf();
  const [copied, setCopied] = useState(false);
  const [actionDone, setActionDone] = useState(false);

  if (!event) return null;

  const handleCopyRaw = () => {
    const raw = `${event.method} ${event.path} HTTP/1.1\nHost: target-application.internal\nUser-Agent: ${event.user_agent || "Unknown"}\nX-Waffynx-Rule: ${event.rule_id}\n\n[Matched Field: ${event.matched_field}]\n${event.matched_value}`;
    navigator.clipboard.writeText(raw);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleQuickMitigate = async () => {
    await unbanIP(event.remote_ip);
    setActionDone(true);
    setTimeout(() => setActionDone(false), 2500);
  };

  return (
    <aside className="forensic-drawer-overlay" onClick={onClose}>
      <div className="forensic-drawer" onClick={(e) => e.stopPropagation()}>
        {/* Drawer Header */}
        <div className="drawer-header">
          <div className="drawer-title-group">
            <span className="drawer-pretitle">DEEP PACKET FORENSICS</span>
            <h2 className="drawer-rule-title">{event.rule_id}</h2>
          </div>
          <button type="button" className="drawer-close-btn" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </div>

        {/* Severity Banner */}
        <div className="drawer-banner">
          <Badge variant="critical">BLOCK (403 FORBIDDEN)</Badge>
          <span className="drawer-banner-meta">
            Mitigated at {new Date(event.timestamp).toLocaleString()}
          </span>
        </div>

        {/* Key Attributes Grid */}
        <div className="drawer-grid">
          <div className="drawer-cell">
            <span className="drawer-cell-label">Source IP</span>
            <span className="drawer-cell-value cyan">{event.remote_ip}</span>
          </div>
          <div className="drawer-cell">
            <span className="drawer-cell-label">HTTP Method</span>
            <span className="drawer-cell-value">{event.method}</span>
          </div>
          <div className="drawer-cell">
            <span className="drawer-cell-label">Matched Field</span>
            <span className="drawer-cell-value purple">{event.matched_field}</span>
          </div>
          <div className="drawer-cell">
            <span className="drawer-cell-label">ML Anomaly Score</span>
            <span className="drawer-cell-value amber">
              {event.anomaly_score ? `${(event.anomaly_score * 100).toFixed(1)}%` : "N/A"}
            </span>
          </div>
        </div>

        {/* Matched Hostile Payload */}
        <div className="drawer-section">
          <h3 className="drawer-section-title">Intercepted Hostile Payload</h3>
          <div className="payload-box">
            <code>{highlightPayload(event.matched_value || event.path)}</code>
          </div>
        </div>

        {/* Request Path & Metadata */}
        <div className="drawer-section">
          <h3 className="drawer-section-title">Full Request URI</h3>
          <div className="uri-box">
            <code>{event.path}</code>
          </div>
        </div>

        {/* Recommended Actions */}
        <div className="drawer-section">
          <h3 className="drawer-section-title">Recommended SOC Playbook</h3>
          <div className="playbook-box">
            <p>
              • IP <code>{event.remote_ip}</code> has been flagged for automated signature evasion.
            </p>
            <p>
              • Kernel-level rule active in <strong>nftables</strong> drop chain.
            </p>
          </div>
        </div>

        {/* Footer Actions */}
        <div className="drawer-footer">
          <button type="button" className="btn-secondary" onClick={handleCopyRaw}>
            {copied ? "✓ Copied to Clipboard" : "📋 Copy Raw Request"}
          </button>
          <button type="button" className="btn-primary-danger" onClick={handleQuickMitigate}>
            {actionDone ? "✓ State Updated" : "🛡️ Update Edge Ban"}
          </button>
        </div>
      </div>
    </aside>
  );
};
