import React from "react";
import type { ViewTab } from "./Sidebar";
import { useAuth } from "../../context/AuthContext";
import { useWaf } from "../../context/WafContext";
import { IconFlask, IconShield } from "../common/Icons";

interface TopbarProps {
  currentTab: ViewTab;
}

const TAB_TITLES: Record<ViewTab, { title: string; subtitle: string }> = {
  overview: {
    title: "Overview",
    subtitle: "Blocks per minute and stored history reported by the control plane",
  },
  events: {
    title: "Security Events",
    subtitle: "Stored history plus the live stream, newest first",
  },
  sites: {
    title: "Sites & Upstreams",
    subtitle: "Reverse-proxy topology: hostname, upstream, TLS and path rules, applied with nginx -t",
  },
  policies: {
    title: "Security Policies & Rule Matrix",
    subtitle: "Active signature sets, OWASP CRS rules, and engine thresholds",
  },
  firewall: {
    title: "Host Firewall & Edge Ban Synchronization",
    subtitle: "L3/L4 nftables & UFW kernel drop tables",
  },
};

export const Topbar: React.FC<TopbarProps> = ({ currentTab }) => {
  const { session, logout } = useAuth();
  const { connected, loadError, status } = useWaf();
  const viewInfo = TAB_TITLES[currentTab] || {
    title: "Waffynx Control Room",
    subtitle: "Unified Network & Application Security",
  };

  return (
    <header className="topbar">
      <div className="topbar-title-group">
        <h1 className="topbar-heading">{viewInfo.title}</h1>
        <p className="topbar-subheading">{viewInfo.subtitle}</p>
      </div>

      <div className="topbar-actions">
        {loadError && (
          <span className="dev-pill" title={loadError}>
            <IconFlask size={13} /> CONTROL PLANE UNREACHABLE
          </span>
        )}

        <div className="connection-pill">
          <span className={`conn-dot ${connected ? "connected" : "reconnecting"}`} />
          <span className="conn-text">{connected ? "Live Stream" : "Connecting..."}</span>
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
