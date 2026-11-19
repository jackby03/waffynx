import React from "react";
import {
  ChevronRight,
  LogOut,
  Menu,
  Monitor,
  Moon,
  Pause,
  Play,
  RefreshCw,
  Search,
  Sun,
} from "lucide-react";
import { navEntryFor, type ViewId } from "../../router/routes";
import { useAuth } from "../../context/AuthContext";
import { useWaf } from "../../context/WafContext";
import { useTheme, type ColorSchemePreference } from "../../context/ThemeContext";

interface TopbarProps {
  currentView: ViewId;
  onOpenPalette: () => void;
  onOpenMobileNav: () => void;
}

const THEME_OPTIONS: { id: ColorSchemePreference; label: string; icon: React.ReactNode }[] = [
  { id: "system", label: "System theme", icon: <Monitor size={14} /> },
  { id: "dark", label: "Dark theme", icon: <Moon size={14} /> },
  { id: "light", label: "Light theme", icon: <Sun size={14} /> },
];

export const Topbar: React.FC<TopbarProps> = ({
  currentView,
  onOpenPalette,
  onOpenMobileNav,
}) => {
  const { session, logout } = useAuth();
  const { connected, paused, bufferedCount, togglePaused, refreshAll, loadingInitial } = useWaf();
  const { preference, setPreference } = useTheme();
  const entry = navEntryFor(currentView);

  return (
    <header className="app-topbar">
      <div className="topbar-left">
        <button
          type="button"
          className="btn btn-ghost btn-icon mobile-menu-btn"
          onClick={onOpenMobileNav}
          aria-label="Open navigation menu"
        >
          <Menu size={18} />
        </button>

        <div className="topbar-breadcrumb">
          <span className="topbar-section">{entry.section}</span>
          <ChevronRight size={14} color="var(--text-muted)" className="topbar-section" aria-hidden="true" />
          <span className="topbar-title">{entry.label}</span>
        </div>
      </div>

      <div className="topbar-right">
        <button type="button" className="cmd-trigger" onClick={onOpenPalette} aria-label="Open command palette">
          <Search size={14} aria-hidden="true" />
          <span className="cmd-trigger-text">Jump to…</span>
          <span className="kbd-hint">Ctrl K</span>
        </button>

        <button
          type="button"
          className={`status-pill ${!connected ? "offline" : paused ? "paused" : "live"}`}
          onClick={togglePaused}
          title={paused ? "Click to resume live event ingestion" : "Click to pause live event ingestion"}
        >
          <span className="pulse-dot" aria-hidden="true" />
          {!connected ? (
            <span>Reconnecting</span>
          ) : paused ? (
            <>
              <Play size={12} aria-hidden="true" />
              <span>Paused{bufferedCount > 0 ? ` (+${bufferedCount})` : ""}</span>
            </>
          ) : (
            <>
              <Pause size={12} aria-hidden="true" />
              <span>SSE Live</span>
            </>
          )}
        </button>

        <button
          type="button"
          className="btn btn-ghost btn-icon"
          onClick={() => void refreshAll()}
          disabled={loadingInitial}
          aria-label="Refresh control plane data"
          title="Refresh data"
        >
          <RefreshCw size={15} />
        </button>

        <div className="theme-segmented" role="group" aria-label="Color theme">
          {THEME_OPTIONS.map((opt) => (
            <button
              key={opt.id}
              type="button"
              className="theme-seg-btn"
              aria-pressed={preference === opt.id}
              aria-label={opt.label}
              title={opt.label}
              onClick={() => setPreference(opt.id)}
            >
              {opt.icon}
            </button>
          ))}
        </div>

        {session && (
          <div className="user-chip">
            <span className="user-avatar" aria-hidden="true">
              {session.username.charAt(0).toUpperCase()}
            </span>
            <div className="user-meta">
              <span className="user-name">{session.username}</span>
              <span className="user-role">{session.role}</span>
            </div>
            <button
              type="button"
              className="btn btn-ghost btn-icon"
              onClick={logout}
              aria-label="Sign out"
              title="Sign out"
            >
              <LogOut size={15} />
            </button>
          </div>
        )}
      </div>
    </header>
  );
};
