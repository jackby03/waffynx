import React, { useState } from "react";
import { useAuth } from "./context/AuthContext";
import { useWaf } from "./context/WafContext";
import { Sidebar, type ViewTab } from "./components/layout/Sidebar";
import { Topbar } from "./components/layout/Topbar";
import { ThreatTicker } from "./components/layout/ThreatTicker";
import { ThreatRadar } from "./views/ThreatRadar/ThreatRadar";
import { AttackForensics } from "./views/AttackForensics/AttackForensics";
import { ForensicDrawer } from "./views/AttackForensics/ForensicDrawer";
import { SecurityPolicies } from "./views/SecurityPolicies/SecurityPolicies";
import { HostFirewall } from "./views/HostFirewall/HostFirewall";
import { MarketplaceView } from "./views/Marketplace/MarketplaceView";
import { TrafficDirector } from "./views/TrafficDirector/TrafficDirector";
import { BotDefense } from "./views/BotDefense/BotDefense";

export const App: React.FC = () => {
  const { isAuthenticated, login } = useAuth();
  const { events, bannedIPs, selectedEvent, setSelectedEvent } = useWaf();

  const [currentTab, setCurrentTab] = useState<ViewTab>("threats");

  // Login form state
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("admin");
  const [loginError, setLoginError] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoginError("");
    setIsSubmitting(true);
    try {
      await login(username, password);
    } catch (err: unknown) {
      if (err instanceof Error) {
        setLoginError(err.message);
      } else {
        setLoginError("Login failed");
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  // If not authenticated, render modern dark login screen
  if (!isAuthenticated) {
    return (
      <div className="login-screen">
        <div className="login-glow-blob-1" />
        <div className="login-glow-blob-2" />

        <div className="login-card">
          <div className="login-header">
            <div className="brand-logo">
              <span className="brand-icon">W</span>
              <div className="brand-text">
                <span className="brand-title">WAFFYNX</span>
                <span className="brand-sub">CONTROL ROOM</span>
              </div>
            </div>
            <h2 className="login-title">Enterprise Authentication</h2>
            <p className="login-subtitle">
              Sign in to manage edge inspection policies and live SOC telemetry
            </p>
          </div>

          <form className="login-form" onSubmit={handleLoginSubmit}>
            {loginError && <div className="login-error">{loginError}</div>}

            <div className="form-field">
              <label className="form-label" htmlFor="username">
                Username
              </label>
              <input
                id="username"
                type="text"
                className="form-input"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoFocus
                required
              />
            </div>

            <div className="form-field">
              <label className="form-label" htmlFor="password">
                Password
              </label>
              <input
                id="password"
                type="password"
                className="form-input"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>

            <button type="submit" className="login-btn" disabled={isSubmitting}>
              {isSubmitting ? "Authenticating..." : "Access Control Room"}
            </button>

            <p className="login-footer-hint">Default credentials: admin / admin</p>
          </form>
        </div>
      </div>
    );
  }

  return (
    <div className="app-layout">
      {/* Sidebar Navigation */}
      <Sidebar
        currentTab={currentTab}
        onSelectTab={setCurrentTab}
        threatCount={events.length}
        bannedCount={bannedIPs.length}
      />

      {/* Main Content Area */}
      <main className="main-content">
        <Topbar currentTab={currentTab} />
        <ThreatTicker
          events={events}
          onSelectEvent={(e) => setSelectedEvent(e)}
          onViewAll={() => setCurrentTab("forensics")}
        />

        {/* Tab Views */}
        {currentTab === "threats" && (
          <ThreatRadar onSelectEvent={(e) => setSelectedEvent(e)} />
        )}
        {currentTab === "forensics" && <AttackForensics />}
        {currentTab === "bot" && <BotDefense />}
        {currentTab === "traffic" && <TrafficDirector />}
        {currentTab === "policies" && <SecurityPolicies />}
        {currentTab === "firewall" && <HostFirewall />}
        {currentTab === "marketplace" && <MarketplaceView />}
      </main>

      {/* Global Forensic Drawer if opened from Ticker/Radar while in any tab */}
      {currentTab !== "forensics" && (
        <ForensicDrawer event={selectedEvent} onClose={() => setSelectedEvent(null)} />
      )}
    </div>
  );
};
