import React from "react";
import {
  IconGlobe,
  IconSearch,
  IconBot,
  IconArrows,
  IconShield,
  IconFirewall,
  IconPlug,
} from "../common/Icons";

export type ViewTab = "threats" | "forensics" | "bot" | "traffic" | "policies" | "firewall" | "marketplace";

interface SidebarProps {
  currentTab: ViewTab;
  onSelectTab: (tab: ViewTab) => void;
  threatCount: number;
  bannedCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentTab,
  onSelectTab,
  threatCount,
  bannedCount,
}) => {
  const navItems: {
    id: ViewTab;
    label: string;
    icon: React.ReactNode;
    section: string;
    badge?: number;
    badgeVariant?: "red" | "cyan";
  }[] = [
    { id: "threats", label: "Threat Radar", icon: <IconGlobe size={18} />, section: "SECURITY OPS" },
    {
      id: "forensics",
      label: "Attack Forensics",
      icon: <IconSearch size={18} />,
      section: "SECURITY OPS",
      badge: threatCount,
      badgeVariant: "red",
    },
    { id: "bot", label: "Bot Defense", icon: <IconBot size={18} />, section: "SECURITY OPS" },
    { id: "traffic", label: "Reverse Proxy & Traffic", icon: <IconArrows size={18} />, section: "TRAFFIC & PROXY" },
    { id: "policies", label: "Security Policies", icon: <IconShield size={18} />, section: "ENFORCEMENT & L3-L7" },
    {
      id: "firewall",
      label: "Host Firewall",
      icon: <IconFirewall size={18} />,
      section: "ENFORCEMENT & L3-L7",
      badge: bannedCount,
      badgeVariant: "cyan",
    },
    { id: "marketplace", label: "AppSec Marketplace", icon: <IconPlug size={18} />, section: "EXTENSIONS" },
  ];

  const sections = Array.from(new Set(navItems.map((n) => n.section)));

  return (
    <nav className="sidebar" aria-label="Waffynx Navigation">
      <div className="sidebar-brand">
        <div className="brand-logo">
          <span className="brand-icon">W</span>
          <div className="brand-text">
            <span className="brand-title">WAFFYNX</span>
            <span className="brand-sub">ENTERPRISE SOC</span>
          </div>
        </div>
      </div>

      <div className="sidebar-links">
        {sections.map((sec) => (
          <div key={sec} className="nav-group">
            <span className="nav-group-label">{sec}</span>
            {navItems
              .filter((item) => item.section === sec)
              .map((item) => (
                <button
                  key={item.id}
                  type="button"
                  className={`nav-btn ${currentTab === item.id ? "active" : ""}`}
                  onClick={() => onSelectTab(item.id)}
                >
                  <span className="nav-icon">{item.icon}</span>
                  <span className="nav-label">{item.label}</span>
                  {item.badge !== undefined && item.badge > 0 && (
                    <span className={`nav-badge ${item.badgeVariant || "cyan"}`}>
                      {item.badge > 99 ? "99+" : item.badge}
                    </span>
                  )}
                </button>
              ))}
          </div>
        ))}
      </div>

      <div className="sidebar-footer">
        <div className="core-status">
          <span className="status-dot online" />
          <span>Core: Online (L7 Pipeline)</span>
        </div>
        <div className="version-info">v0.2.0 • Zero-Copy Sidecar</div>
      </div>
    </nav>
  );
};
