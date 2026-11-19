import React, { useCallback, useEffect, useState } from "react";
import { useAuth } from "./context/AuthContext";
import { useWaf } from "./context/WafContext";
import { navEntryFor, viewFromPathname, type ViewId } from "./router/routes";
import { Sidebar } from "./components/layout/Sidebar";
import { Topbar } from "./components/layout/Topbar";
import { CommandPalette } from "./components/layout/CommandPalette";
import { Dialog } from "./components/common/Dialog";
import { ErrorBoundary } from "./components/common/ErrorBoundary";
import { LoginView } from "./views/Login/LoginView";
import { OverviewView } from "./views/Overview/OverviewView";
import { EventsView } from "./views/Events/EventsView";
import { EventDetailDialog } from "./views/Events/EventDetailDialog";
import { SitesView } from "./views/Sites/SitesView";
import { ZeroTrustView } from "./views/ZeroTrust/ZeroTrustView";
import { SecurityPolicies } from "./views/SecurityPolicies/SecurityPolicies";
import { CustomRulesView } from "./views/CustomRules/CustomRulesView";
import { IpBans } from "./views/HostFirewall/IpBans";
import { LearningView } from "./views/Learning/LearningView";
import { PipelineView } from "./views/Pipeline/PipelineView";
import { MarketplaceView } from "./views/Marketplace/MarketplaceView";
import { AuditView } from "./views/Audit/AuditView";
import { SystemView } from "./views/System/SystemView";

const RAIL_STORAGE_KEY = "waffynx_rail_collapsed";

export const App: React.FC = () => {
  const { isAuthenticated } = useAuth();
  const { inspectedEvent, setInspectedEvent } = useWaf();

  const [currentView, setCurrentView] = useState<ViewId>(() =>
    viewFromPathname(window.location.pathname)
  );
  const [presetQuery, setPresetQuery] = useState("");
  const [railCollapsed, setRailCollapsed] = useState<boolean>(() => {
    try {
      return localStorage.getItem(RAIL_STORAGE_KEY) === "1";
    } catch {
      return false;
    }
  });
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);

  const navigate = useCallback((view: ViewId, query = "") => {
    const entry = navEntryFor(view);
    setCurrentView(view);
    setPresetQuery(query);
    setMobileNavOpen(false);
    if (window.location.pathname !== entry.path) {
      window.history.pushState({ view }, "", entry.path);
    }
    requestAnimationFrame(() => {
      document.getElementById("view-heading")?.focus();
    });
  }, []);

  // Sync browser back/forward navigation
  useEffect(() => {
    const onPopState = () => {
      setCurrentView(viewFromPathname(window.location.pathname));
    };
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  // Keep unique SPA document title per screen (WCAG 2.4.2)
  useEffect(() => {
    if (!isAuthenticated) {
      document.title = "Sign In | Waffynx Control Room";
      return;
    }
    const entry = navEntryFor(currentView);
    document.title = `${entry.label} | Waffynx Control Room`;
  }, [isAuthenticated, currentView]);

  // Global Cmd+K / Ctrl+K shortcut for Command Palette
  useEffect(() => {
    if (!isAuthenticated) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((prev) => !prev);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [isAuthenticated]);

  const toggleRail = () => {
    setRailCollapsed((prev) => {
      const next = !prev;
      try {
        localStorage.setItem(RAIL_STORAGE_KEY, next ? "1" : "0");
      } catch {
        // Ignore storage failure
      }
      return next;
    });
  };

  if (!isAuthenticated) {
    return <LoginView />;
  }

  return (
    <div className={`app-shell ${railCollapsed ? "rail-collapsed" : ""}`}>
      <a href="#view-heading" className="skip-link visually-hidden">
        Skip to main content
      </a>

      <Sidebar
        currentView={currentView}
        collapsed={railCollapsed}
        onToggleCollapse={toggleRail}
        onSelectView={(v) => navigate(v)}
      />

      <Topbar
        currentView={currentView}
        onOpenPalette={() => setPaletteOpen(true)}
        onOpenMobileNav={() => setMobileNavOpen(true)}
      />

      <main className="app-main" id="main-content">
        <ErrorBoundary>
          {currentView === "overview" && <OverviewView onNavigate={navigate} />}
          {currentView === "events" && <EventsView initialQuery={presetQuery} />}
          {currentView === "sites" && <SitesView initialQuery={presetQuery} />}
          {currentView === "zero-trust" && <ZeroTrustView />}
          {currentView === "managed-rules" && <SecurityPolicies initialQuery={presetQuery} />}
          {currentView === "custom-rules" && <CustomRulesView />}
          {currentView === "firewall" && <IpBans />}
          {currentView === "learning" && <LearningView />}
          {currentView === "pipeline" && <PipelineView />}
          {currentView === "marketplace" && <MarketplaceView />}
          {currentView === "audit" && <AuditView />}
          {currentView === "system" && <SystemView />}
        </ErrorBoundary>
      </main>

      {/* Mobile Navigation Drawer */}
      <Dialog
        open={mobileNavOpen}
        onClose={() => setMobileNavOpen(false)}
        title="Navigation"
        variant="nav-drawer"
        hideHeader
      >
        <Sidebar
          currentView={currentView}
          collapsed={false}
          onSelectView={(v) => navigate(v)}
          mobile
        />
      </Dialog>

      {/* Command Palette (Ctrl+K / Cmd+K) */}
      <CommandPalette
        open={paletteOpen}
        onClose={() => setPaletteOpen(false)}
        onNavigate={navigate}
      />

      {/* Unified Deep Packet Forensic Drawer */}
      <EventDetailDialog
        event={inspectedEvent}
        onClose={() => setInspectedEvent(null)}
      />
    </div>
  );
};
