import { StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { api, clearToken, getToken, setToken, type Plugin, type Status, type Metrics, type WafEvent } from "./services/api";
import { streamEvents } from "./services/event-stream";
import "./styles.css";

function Login({ onLogin }: { onLogin: () => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const response = await api.login(username, password);
      setToken(response.token);
      onLogin();
    } catch {
      setError("Unable to authenticate with the control plane.");
    } finally {
      setBusy(false);
    }
  }

  return <main className="login-shell"><form className="login-card" onSubmit={submit}>
    <div className="eyebrow">WAFFYNX / CONTROL PLANE</div>
    <h1>See the attack surface clearly.</h1>
    <p className="muted">Secure operational visibility for your edge.</p>
    <label>Username<input autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required /></label>
    <label>Password<input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required /></label>
    <button disabled={busy}>{busy ? "Authenticating..." : "Enter control room"}</button>
    {error && <p className="error" role="alert">{error}</p>}
  </form></main>;
}

function Dashboard({ onLogout }: { onLogout: () => void }) {
  const [status, setStatus] = useState<Status | null>(null);
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [plugins, setPlugins] = useState<Plugin[]>([]);
  const [events, setEvents] = useState<WafEvent[]>([]);
  const [connection, setConnection] = useState("connecting");
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    Promise.all([api.status(), api.metrics(), api.plugins()]).then(([nextStatus, nextMetrics, nextPlugins]) => {
      if (!active) return;
      setStatus(nextStatus);
      setMetrics(nextMetrics);
      setPlugins(nextPlugins);
    }).catch((err: unknown) => {
      if (!active) return;
      if (err instanceof Error && err.message === "unauthorized") onLogout();
      else setError(err instanceof Error ? err.message : "Unable to load dashboard data");
    });
    const stop = streamEvents((event) => {
      if (event.type === "blocked") setEvents((current) => [event, ...current].slice(0, 50));
    }, setConnection, onLogout);
    return () => { active = false; stop(); };
  }, []);

  return <div className="app-shell">
    <header className="topbar"><div><div className="eyebrow">WAFFYNX / OPERATIONS</div><h1>Control room</h1></div><div className="top-actions"><span className={`connection ${connection}`}>{connection}</span><button className="ghost" onClick={onLogout}>Sign out</button></div></header>
    {error && <div className="banner error" role="alert">{error}</div>}
    <main className="content">
      <section className="hero"><div><p className="kicker">Live perimeter intelligence</p><h2>Know what is happening before it becomes an incident.</h2></div><div className="hero-mark">W</div></section>
      <section className="stats-grid">
        <article className="stat"><span>Engine</span><strong>{status ? "Online" : "Loading"}</strong><small>{status?.go_version ?? "Awaiting status"}</small></article>
        <article className="stat"><span>Heap allocated</span><strong>{metrics ? `${Math.round(metrics.go.heap_alloc / 1024 / 1024)} MB` : "--"}</strong><small>{metrics?.go.goroutines ?? "--"} goroutines</small></article>
        <article className="stat accent"><span>Live blocks</span><strong>{events.length}</strong><small>Recent security events</small></article>
        <article className="stat"><span>Plugins</span><strong>{plugins.length}</strong><small>Registered modules</small></article>
      </section>
      <section className="panel"><div className="panel-head"><div><p className="kicker">STREAM / BLOCKED REQUESTS</p><h3>Live attack feed</h3></div><span className="live-dot">● streaming</span></div>
        {events.length === 0 ? <div className="empty">No blocked events received yet.</div> : <div className="event-list">{events.map((event, index) => <article className="event" key={`${event.timestamp}-${event.rule_id}-${index}`}><div className="event-bar" /><div className="event-main"><div className="event-line"><strong>{event.rule_id}</strong><span>{event.method}</span><time>{formatTime(event.timestamp)}</time></div><code>{event.path}</code><p>{event.reason || "Blocked by Waffynx policy"}</p></div><div className="event-ip">{event.remote_ip}</div></article>)}</div>}
      </section>
      <section className="lower-grid"><div className="panel"><div className="panel-head"><div><p className="kicker">MODULES</p><h3>Active plugins</h3></div></div>{plugins.length === 0 ? <div className="empty">No plugin data available.</div> : <ul className="plugin-list">{plugins.map((plugin) => <li key={plugin.name}><span className="plugin-dot" /><div><strong>{plugin.name}</strong><small>{plugin.description}</small></div><code>v{plugin.version}</code></li>)}</ul>}</div><div className="panel note"><p className="kicker">SECURITY POSTURE</p><h3>Inspection pipeline</h3><p>Requests move through plugins, policy rules, and anomaly scoring before reaching your upstream.</p><div className="pipeline"><span>NGINX</span><i>→</i><span>SIDECAR</span><i>→</i><span>ML</span></div></div></section>
    </main>
  </div>;
}

function formatTime(value: string) { const date = new Date(value); return Number.isNaN(date.valueOf()) ? "now" : date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }); }
function App() { const [authenticated, setAuthenticated] = useState(Boolean(getToken())); const logout = () => { clearToken(); setAuthenticated(false); }; return authenticated ? <Dashboard onLogout={logout} /> : <Login onLogin={() => setAuthenticated(true)} />; }

createRoot(document.getElementById("root")!).render(<StrictMode><App /></StrictMode>);
