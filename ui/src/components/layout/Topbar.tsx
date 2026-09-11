import React from "react";
import type { ViewTab } from "./Sidebar";
import { useAuth } from "../../context/AuthContext";
import { useWaf } from "../../context/WafContext";
import { IconFlask, IconShield } from "../common/Icons";

interface TopbarProps {
  currentTab: ViewTab;
}

const TAB_TITLES: Record<ViewTab, { title: string; subtitle: string }> = {
  threats: {
    title: "Threat Radar & Telemetry",
    subtitle: "Real-time edge inspection metrics and anomaly telemetry",
  },
  forensics: {
    title: "Live Incident Forensics",
    subtitle: "Deep packet inspection and matched signature analysis",
  },
  bot: {
    title: "Bot Defense & Mitigation",
    subtitle: "Automated browser verification, JS proof-of-work challenges, and JA3/JA4 fingerprinting",
  },
  traffic: {
    title: "Reverse Proxy, Traffic & Cloaking",
    subtitle: "Virtual servers, upstream health probes, custom error templates (404/500), and header cloaking",
  },
  policies: {
    title: "Security Policies & Rule Matrix",
    subtitle: "Active signature sets, OWASP CRS rules, and engine thresholds",
  },
  firewall: {
    title: "Host Firewall & Edge Ban Synchronization",
    subtitle: "L3/L4 nftables & UFW kernel drop tables",
  },
  marketplace: {
    title: "AppSec Marketplace & Extensions",
    subtitle: "Modular WAF plugins, detection analyzers, and bridges",
  },
};

export const Topbar: React.FC<TopbarProps> = ({ currentTab }) => {
  const { session, logout } = useAuth();
  const { connected, isMock, status } = useWaf();
  const viewInfo = TAB_TITLES[currentTab] || {
    title: "Waffynx Control Room",
    subtitle: "Unified Network & Application Security",
  };
  const mode = status?.enforcement_mode || "blocking";

  return (
    <header className="topbar">
      <div className="topbar-title-group">
        <h1 className="topbar-heading">{viewInfo.title}</h1>
        <p className="topbar-subheading">{viewInfo.subtitle}</p>
      </div>

      <div className="topbar-actions">
        {isMock && (
          <span className="dev-pill" title="Local mock backend mode active">
            <IconFlask size={13} /> DEV MOCK
          </span>
        )}

        <div className="connection-pill">
          <span className={`conn-dot ${connected ? "connected" : "reconnecting"}`} />
          <span className="conn-text">{connected ? "Live Stream" : "Connecting..."}</span>
        </div>

        <div className={`mode-badge mode-${mode}`}>
          <span className="mode-icon">
            <IconShield size={14} />
          </span>
          <span>MODE: {mode.toUpperCase()}</span>
        </div>

        {session && (
          <div className="user-profile">
            <span className="user-avatar">{session.username.charAt(0).toUpperCase()}</span>
            <span className="user-name">{session.username}</span>
            <button
              type="button"
              className="btn-logout"
              onClick={logout}
              title="Sign out of Waffynx"
            >
              Sign out
            </button>
          </div>
        )}
      </div>
    </header>
  );
};
