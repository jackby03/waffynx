import React, { useState } from "react";
import { AlertCircle, Eye, EyeOff, Lock, Shield } from "lucide-react";
import { useAuth } from "../../context/AuthContext";
import { CodeBlock } from "../../components/common/CodeBlock";

export const LoginView: React.FC = () => {
  const { login } = useAuth();
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setSubmitting(true);
    try {
      await login(username.trim(), password.trim());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Authentication failed");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="login-page">
      <aside className="login-aside">
        <div className="brand-mark">
          <span className="brand-emblem" aria-hidden="true">
            <Shield size={18} strokeWidth={2.3} />
          </span>
          <div className="brand-copy">
            <span className="brand-name" style={{ color: "#f8fafc" }}>
              WAFFYNX
            </span>
            <span className="brand-tag" style={{ color: "#94a3b8" }}>
              Self-Hosted Edge WAF &amp; Reverse Proxy
            </span>
          </div>
        </div>

        <div>
          <h1 className="login-hero-title">Fail-closed L7 inspection on infrastructure you control.</h1>
          <p className="login-hero-copy">
            Native Nginx C module forwarding requests over a 0600 Unix socket to a zero-copy Go
            inspection pipeline: Custom Rules, Aho-Corasick Managed Catalog, Plugins, and Pluggable
            AppSec Scoring.
          </p>

          <div className="login-specs">
            <div className="login-spec-card">
              <div className="login-spec-title">Deterministic Catalog</div>
              <div className="login-spec-desc">
                Single-pass Aho-Corasick normalization across URI, query, headers, and bodies.
              </div>
            </div>
            <div className="login-spec-card">
              <div className="login-spec-title">Strict Plane Separation</div>
              <div className="login-spec-desc">
                Control Plane telemetry and site mutations never sit inline on the data plane.
              </div>
            </div>
            <div className="login-spec-card">
              <div className="login-spec-title">Atomic Proxy Reloads</div>
              <div className="login-spec-desc">
                Every reverse-proxy topology change is verified via nginx -t with automatic rollback.
              </div>
            </div>
            <div className="login-spec-card">
              <div className="login-spec-title">Privilege-Free IP Bans</div>
              <div className="login-spec-desc">
                Enforced directly in the sidecar without NET_ADMIN; optional nftables in system mode.
              </div>
            </div>
          </div>
        </div>

        <div className="mono" style={{ fontSize: "0.75rem", color: "#64748b" }}>
          Control Plane API · JWT / OIDC · Zero Mock Telemetry
        </div>
      </aside>

      <main className="login-form-pane">
        <section className="login-card" aria-labelledby="login-heading">
          <div>
            <div className="dialog-eyebrow">Control Room Sign-In</div>
            <h2 id="login-heading" style={{ fontSize: "1.35rem", fontWeight: 750 }}>
              Authenticate operator session
            </h2>
            <p className="text-secondary" style={{ fontSize: "0.82rem", marginTop: "0.25rem" }}>
              Sign in with your Waffynx Control Plane credentials.
            </p>
          </div>

          <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
            {error && (
              <div className="alert-banner error" id="login-error" role="alert">
                <span className="alert-banner-content">
                  <AlertCircle size={16} aria-hidden="true" />
                  <span>{error}</span>
                </span>
              </div>
            )}

            <div className="field">
              <label className="field-label" htmlFor="login-username">
                Username
              </label>
              <input
                id="login-username"
                type="text"
                className="input"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="username"
                aria-invalid={Boolean(error)}
                aria-describedby={error ? "login-error" : undefined}
                autoFocus
                required
              />
            </div>

            <div className="field">
              <label className="field-label" htmlFor="login-password">
                Password
              </label>
              <div style={{ position: "relative" }}>
                <input
                  id="login-password"
                  type={showPassword ? "text" : "password"}
                  className="input"
                  style={{ paddingInlineEnd: "2.4rem" }}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="current-password"
                  aria-invalid={Boolean(error)}
                  aria-describedby={error ? "login-error" : undefined}
                  required
                />
                <button
                  type="button"
                  className="search-clear-btn"
                  onClick={() => setShowPassword((prev) => !prev)}
                  aria-label={showPassword ? "Hide password" : "Show password"}
                  aria-pressed={showPassword}
                >
                  {showPassword ? <EyeOff size={15} /> : <Eye size={15} />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              className="btn btn-primary"
              disabled={submitting}
              aria-busy={submitting}
              style={{ marginTop: "0.25rem", minBlockSize: 40 }}
            >
              <Lock size={15} aria-hidden="true" />
              <span>{submitting ? "Verifying credentials…" : "Sign in to Control Room"}</span>
            </button>
          </form>

          <details className="login-help">
            <summary>First deployment? Retrieve generated admin password</summary>
            <p style={{ marginBlock: "0.55rem" }}>
              On first boot without <code>WAFFYNX_ADMIN_PASSWORD</code>, Waffynx generates a random
              admin credential once and persists its bcrypt hash inside the data volume:
            </p>
            <CodeBlock
              label="Docker Compose"
              copyText="docker compose logs waffynx | grep password="
            >
              docker compose logs waffynx | grep password=
            </CodeBlock>
          </details>
        </section>
      </main>
    </div>
  );
};
