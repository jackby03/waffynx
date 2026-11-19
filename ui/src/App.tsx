import React, { useState } from "react";
import { useAuth } from "./context/AuthContext";
import { useWaf } from "./context/WafContext";
import { Sidebar, type ViewTab } from "./components/layout/Sidebar";
import { Topbar } from "./components/layout/Topbar";
import { ThreatTicker } from "./components/layout/ThreatTicker";
import { OverviewView } from "./views/Overview/OverviewView";
import { EventsView } from "./views/Events/EventsView";
import { SecurityPolicies } from "./views/SecurityPolicies/SecurityPolicies";
import { IpBans } from "./views/HostFirewall/IpBans";
import { SitesView } from "./views/Sites/SitesView";
import { ErrorBoundary } from "./components/common/ErrorBoundary";

export const App: React.FC = () => {
  const { isAuthenticated, login } = useAuth();
  const { events, bannedIPs } = useWaf();

  const [currentTab, setCurrentTab] = useState<ViewTab>("overview");

  // Login form state
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
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
            {loginError && (
              <div className="login-error" id="login-error" role="alert">
                {loginError}
              </div>
            )}

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
                autoComplete="username"
                aria-invalid={loginError ? true : false}
                aria-describedby={loginError ? "login-error" : undefined}
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
                autoComplete="current-password"
                aria-invalid={loginError ? true : false}
                aria-describedby={loginError ? "login-error" : undefined}
                required
              />
            </div>

            <button type="submit" className="login-btn" disabled={isSubmitting} aria-busy={isSubmitting}>
              {isSubmitting ? "Authenticating..." : "Access Control Room"}
            </button>

            <p className="login-footer-hint">
              First run? The admin password is printed once in the container log:{" "}
              <code>docker logs &lt;container&gt; | grep password=</code>
            </p>
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
          onSelectEvent={() => setCurrentTab("events")}
          onViewAll={() => setCurrentTab("events")}
        />

        {/* Tab Views */}
        <ErrorBoundary>
        {currentTab === "overview" && <OverviewView />}
        {currentTab === "events" && <EventsView />}
        {currentTab === "sites" && <SitesView />}
        {currentTab === "policies" && <SecurityPolicies />}
        {currentTab === "firewall" && <IpBans />}
        </ErrorBoundary>
      </main>
    </div>
  );
};
