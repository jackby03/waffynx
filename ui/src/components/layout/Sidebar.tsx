import React from "react";
import {
  Activity,
  Ban,
  Brain,
  FileText,
  Globe,
  Layers,
  Lock,
  PanelLeftClose,
  PanelLeftOpen,
  Radar,
  Settings,
  Shield,
  ShieldCheck,
  Sliders,
  Store,
} from "lucide-react";
import { NAV_ITEMS, type ViewId } from "../../router/routes";
import { useWaf } from "../../context/WafContext";

const VIEW_ICONS: Record<ViewId, React.ReactNode> = {
  overview: <Radar size={17} />,
  events: <Activity size={17} />,
  sites: <Globe size={17} />,
  "zero-trust": <Lock size={17} />,
  "managed-rules": <ShieldCheck size={17} />,
  "custom-rules": <Sliders size={17} />,
  firewall: <Ban size={17} />,
  learning: <Brain size={17} />,
  pipeline: <Layers size={17} />,
  marketplace: <Store size={17} />,
  audit: <FileText size={17} />,
  system: <Settings size={17} />,
};

interface SidebarProps {
  currentView: ViewId;
  collapsed: boolean;
  onToggleCollapse?: () => void;
  onSelectView: (view: ViewId) => void;
  mobile?: boolean;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentView,
  collapsed,
  onToggleCollapse,
  onSelectView,
  mobile = false,
}) => {
  const { events, sites, bannedIPs, status, metrics, connected } = useWaf();

  const sections = Array.from(new Set(NAV_ITEMS.map((item) => item.section)));
  const heapMB = metrics ? Math.round(metrics.go.heap_alloc / 1024 / 1024) : null;
  const engineName = status?.config?.engine ?? "basic-go";
  const version = status?.version ?? "dev";

  const counterFor = (id: ViewId): { count: number; tone?: "critical" | "info" } | null => {
    if (id === "events" && events.length > 0) return { count: events.length, tone: "critical" };
    if (id === "sites" && sites.length > 0) return { count: sites.length, tone: "info" };
    if (id === "firewall" && bannedIPs.length > 0) return { count: bannedIPs.length, tone: "critical" };
    return null;
  };

  return (
    <nav className={mobile ? "" : "app-rail"} aria-label="Primary" style={mobile ? { display: "flex", flexDirection: "column", height: "100%" } : undefined}>
      <div className="rail-header">
        <div className="brand-mark">
          <span className="brand-emblem" aria-hidden="true">
            <Shield size={17} strokeWidth={2.3} />
          </span>
          <div className="brand-copy">
            <span className="brand-name">WAFFYNX</span>
            <span className="brand-tag">Edge WAF Console</span>
          </div>
        </div>

        {!mobile && onToggleCollapse && (
          <button
            type="button"
            className="btn btn-ghost btn-icon"
            onClick={onToggleCollapse}
            aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          >
            {collapsed ? <PanelLeftOpen size={16} /> : <PanelLeftClose size={16} />}
          </button>
        )}
      </div>

      <div className="rail-scroll">
        {sections.map((section) => (
          <div key={section} className="nav-section">
            <span className="nav-section-title">{section}</span>
            {NAV_ITEMS.filter((item) => item.section === section).map((item) => {
              const badge = counterFor(item.id);
              const active = currentView === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  className={`nav-item ${active ? "active" : ""}`}
                  aria-current={active ? "page" : undefined}
                  onClick={() => onSelectView(item.id)}
                  title={collapsed && !mobile ? item.label : undefined}
                >
                  <span aria-hidden="true">{VIEW_ICONS[item.id]}</span>
                  <span className="nav-item-label">{item.label}</span>
                  {badge && (
                    <span className={`nav-counter ${badge.tone ?? ""}`}>
                      {badge.count > 999 ? "999+" : badge.count}
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        ))}
      </div>

      <div className="rail-footer">
        <div className="rail-status-row">
          <span
            className="pulse-dot"
            style={{ color: connected ? "var(--status-ok)" : "var(--status-high)" }}
            aria-hidden="true"
          />
          <span className="rail-footer-details">
            {connected ? "Control Plane Live" : "Reconnecting…"}
          </span>
        </div>
        <div className="rail-meta rail-footer-details">
          {engineName} · {heapMB !== null ? `${heapMB} MB` : "—"} · {version}
        </div>
      </div>
    </nav>
  );
};
