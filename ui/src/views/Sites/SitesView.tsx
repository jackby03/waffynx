import React, { useEffect, useMemo, useState } from "react";
import {
  Globe,
  Lock,
  Pencil,
  Plus,
  Search,
  Server,
  Trash2,
  Unlock,
  X,
} from "lucide-react";
import { wafApi } from "../../api/wafApi";
import { ApiError } from "../../api/client";
import type { PathRule, Site } from "../../api/types";
import { useWaf } from "../../context/WafContext";
import { useToast } from "../../context/ToastContext";
import { KpiCard } from "../../components/common/KpiCard";
import { Badge } from "../../components/common/Badge";
import { EmptyState } from "../../components/common/EmptyState";
import { Dialog } from "../../components/common/Dialog";
import { ConfirmDialog } from "../../components/common/ConfirmDialog";
import { CodeBlock } from "../../components/common/CodeBlock";
import { validateSite, type SiteFieldErrors } from "../../utils/validators";

type EditorTab = "general" | "tls" | "paths" | "plugins" | "preview";

interface HeaderRow {
  key: string;
  value: string;
}

function buildNginxPreview(site: Site): string {
  const host = site.host.trim().toLowerCase() || "app.example.com";
  const upstream = site.upstream.trim() || "backend:8080";
  const proxyTarget = upstream.includes("://") ? upstream : `http://${upstream}`;
  const hasTls = Boolean(site.tls?.cert_file.trim() && site.tls?.key_file.trim());

  const lines: string[] = [
    `server {`,
    hasTls ? `    listen 8443 ssl;` : `    listen 8080;`,
    `    server_name ${host};`,
  ];

  if (hasTls && site.tls) {
    lines.push(
      `    ssl_certificate     ${site.tls.cert_file.trim()};`,
      `    ssl_certificate_key ${site.tls.key_file.trim()};`
    );
  }

  lines.push(
    ``,
    `    # Waffynx zero-copy inspection (ACCESS phase -> 0600 Unix socket)`,
    `    waffynx on;`,
    `    waffynx_socket /opt/waffynx/waffynx.sock;`
  );

  for (const [k, v] of Object.entries(site.headers ?? {})) {
    if (k.trim()) {
      lines.push(`    add_header ${k.trim()} "${v}";`);
    }
  }

  for (const pr of site.paths ?? []) {
    if (!pr.path.trim()) continue;
    const target = pr.upstream?.trim()
      ? pr.upstream.includes("://")
        ? pr.upstream.trim()
        : `http://${pr.upstream.trim()}`
      : proxyTarget;
    lines.push(
      ``,
      `    location ${pr.path.trim()} {`,
      `        proxy_pass ${target};`,
      `    }`
    );
  }

  lines.push(
    ``,
    `    location / {`,
    `        proxy_pass ${proxyTarget};`,
    `        proxy_set_header Host $host;`,
    `        proxy_set_header X-Real-IP $remote_addr;`,
    `    }`,
    `}`
  );
  return lines.join("\n");
}

interface SitesViewProps {
  initialQuery?: string;
}

export const SitesView: React.FC<SitesViewProps> = ({ initialQuery = "" }) => {
  const { sites, plugins, refreshSites } = useWaf();
  const { pushToast } = useToast();

  const [query, setQuery] = useState(initialQuery);
  const [tlsFilter, setTlsFilter] = useState<"all" | "tls" | "http">("all");
  const [loadError, setLoadError] = useState("");

  // Editor drawer state
  const [editorOpen, setEditorOpen] = useState(false);
  const [editingHost, setEditingHost] = useState<string | null>(null);
  const [editorTab, setEditorTab] = useState<EditorTab>("general");
  const [host, setHost] = useState("");
  const [upstream, setUpstream] = useState("");
  const [certFile, setCertFile] = useState("");
  const [keyFile, setKeyFile] = useState("");
  const [paths, setPaths] = useState<PathRule[]>([]);
  const [selectedPlugins, setSelectedPlugins] = useState<string[]>([]);
  const [headerRows, setHeaderRows] = useState<HeaderRow[]>([]);
  const [fieldErrors, setFieldErrors] = useState<SiteFieldErrors>({});
  const [formError, setFormError] = useState("");
  const [saving, setSaving] = useState(false);

  // Delete confirmation state
  const [pendingDelete, setPendingDelete] = useState<Site | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState("");

  useEffect(() => {
    if (initialQuery) setQuery(initialQuery);
  }, [initialQuery]);

  const reload = async () => {
    setLoadError("");
    try {
      await refreshSites();
    } catch (err) {
      setLoadError(err instanceof ApiError ? err.message : "Could not load sites.");
    }
  };

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return sites.filter((s) => {
      if (tlsFilter === "tls" && !s.tls) return false;
      if (tlsFilter === "http" && s.tls) return false;
      if (!q) return true;
      return (
        s.host.toLowerCase().includes(q) ||
        s.upstream.toLowerCase().includes(q) ||
        (s.paths ?? []).some((p) => p.path.toLowerCase().includes(q))
      );
    });
  }, [sites, query, tlsFilter]);

  const tlsCount = useMemo(() => sites.filter((s) => Boolean(s.tls)).length, [sites]);
  const totalPaths = useMemo(() => sites.reduce((acc, s) => acc + (s.paths?.length ?? 0), 0), [sites]);
  const totalHeaders = useMemo(
    () => sites.reduce((acc, s) => acc + Object.keys(s.headers ?? {}).length, 0),
    [sites]
  );

  const openCreate = () => {
    setEditingHost(null);
    setEditorTab("general");
    setHost("");
    setUpstream("");
    setCertFile("");
    setKeyFile("");
    setPaths([]);
    setSelectedPlugins([]);
    setHeaderRows([]);
    setFieldErrors({});
    setFormError("");
    setEditorOpen(true);
  };

  const openEdit = (site: Site) => {
    setEditingHost(site.host);
    setEditorTab("general");
    setHost(site.host);
    setUpstream(site.upstream);
    setCertFile(site.tls?.cert_file ?? "");
    setKeyFile(site.tls?.key_file ?? "");
    setPaths(site.paths ? site.paths.map((p) => ({ ...p })) : []);
    setSelectedPlugins(site.plugins ? [...site.plugins] : []);
    setHeaderRows(
      Object.entries(site.headers ?? {}).map(([key, value]) => ({ key, value }))
    );
    setFieldErrors({});
    setFormError("");
    setEditorOpen(true);
  };

  const buildCandidateSite = (): Site => {
    const candidate: Site = {
      host: host.trim().toLowerCase(),
      upstream: upstream.trim(),
    };
    if (certFile.trim() || keyFile.trim()) {
      candidate.tls = { cert_file: certFile.trim(), key_file: keyFile.trim() };
    }
    const cleanPaths = paths
      .map((p) => ({
        path: p.path.trim(),
        ...(p.upstream?.trim() ? { upstream: p.upstream.trim() } : {}),
      }))
      .filter((p) => p.path !== "");
    if (cleanPaths.length > 0) candidate.paths = cleanPaths;

    if (selectedPlugins.length > 0) candidate.plugins = selectedPlugins;

    const cleanHeaders: Record<string, string> = {};
    for (const row of headerRows) {
      if (row.key.trim()) cleanHeaders[row.key.trim()] = row.value;
    }
    if (Object.keys(cleanHeaders).length > 0) candidate.headers = cleanHeaders;

    return candidate;
  };

  const submitSite = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError("");
    const candidate = buildCandidateSite();
    const errors = validateSite(candidate);
    setFieldErrors(errors);

    if (Object.keys(errors).length > 0) {
      if (errors.host || errors.upstream) setEditorTab("general");
      else if (errors.tls) setEditorTab("tls");
      else if (errors.paths) setEditorTab("paths");
      else if (errors.headers) setEditorTab("plugins");
      return;
    }

    setSaving(true);
    try {
      if (editingHost) {
        await wafApi.updateSite(editingHost, candidate);
        pushToast("ok", `Updated ${candidate.host}`, "Validated with nginx -t and reloaded.");
      } else {
        await wafApi.createSite(candidate);
        pushToast("ok", `Protected site ${candidate.host} added`, "Validated with nginx -t and active.");
      }
      setEditorOpen(false);
      await refreshSites();
    } catch (err) {
      setFormError(err instanceof ApiError ? err.message : "Could not apply site configuration.");
    } finally {
      setSaving(false);
    }
  };

  const confirmDelete = async () => {
    if (!pendingDelete) return;
    setDeleting(true);
    setDeleteError("");
    try {
      await wafApi.deleteSite(pendingDelete.host);
      pushToast("info", `Removed ${pendingDelete.host}`, "Nginx fragment deleted and reloaded.");
      setPendingDelete(null);
      await refreshSites();
    } catch (err) {
      setDeleteError(err instanceof ApiError ? err.message : "Could not delete site.");
    } finally {
      setDeleting(false);
    }
  };

  const togglePlugin = (name: string) => {
    setSelectedPlugins((prev) =>
      prev.includes(name) ? prev.filter((p) => p !== name) : [...prev, name]
    );
  };

  const draftPreview = useMemo(
    () => buildNginxPreview(buildCandidateSite()),
    [host, upstream, certFile, keyFile, paths, selectedPlugins, headerRows]
  );

  return (
    <div className="canvas-inner">
      <header className="view-header">
        <div>
          <h1 className="view-title" id="view-heading" tabIndex={-1}>
            Protected Sites &amp; Reverse Proxy
          </h1>
          <p className="view-subtitle">
            Host-to-upstream topology rendered into Nginx fragments. Every create, update, or delete
            is verified with <code>nginx -t</code> before touching disk and rolled back on rejection.
          </p>
        </div>
        <div className="view-actions">
          <button type="button" className="btn btn-primary" onClick={openCreate}>
            <Plus size={15} aria-hidden="true" />
            <span>Add Protected Site</span>
          </button>
        </div>
      </header>

      {loadError && (
        <div className="alert-banner error" role="alert">
          <span>{loadError}</span>
          <button type="button" className="btn btn-sm" onClick={() => void reload()}>
            Retry
          </button>
        </div>
      )}

      <section className="kpi-grid">
        <KpiCard title="Protected Hosts" value={sites.length} subtext="Active reverse-proxy blocks" tone="info" />
        <KpiCard title="TLS / HTTPS" value={tlsCount} subtext={`${sites.length - tlsCount} plain HTTP`} tone="ok" />
        <KpiCard title="Path Rules" value={totalPaths} subtext="Custom prefix upstream routes" tone="default" />
        <KpiCard title="Custom Headers" value={totalHeaders} subtext="Injected security headers" tone="ml" />
      </section>

      <section className="panel">
        <div className="filter-bar">
          <div className="filter-row">
            <div className="search-wrap">
              <Search size={15} className="search-wrap-icon" aria-hidden="true" />
              <label htmlFor="sites-search" className="visually-hidden">
                Filter protected sites
              </label>
              <input
                id="sites-search"
                type="search"
                className="search-input"
                placeholder="Filter by hostname, wildcard, upstream, or path…"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
              />
              {query && (
                <button
                  type="button"
                  className="search-clear-btn"
                  onClick={() => setQuery("")}
                  aria-label="Clear filter"
                >
                  <X size={13} />
                </button>
              )}
            </div>

            <div className="pill-group" role="group" aria-label="Filter by TLS mode">
              {([
                { id: "all", label: "All" },
                { id: "tls", label: "HTTPS / TLS" },
                { id: "http", label: "Plain HTTP" },
              ] as const).map((opt) => (
                <button
                  key={opt.id}
                  type="button"
                  className="pill"
                  aria-pressed={tlsFilter === opt.id}
                  onClick={() => setTlsFilter(opt.id)}
                >
                  {opt.label}
                </button>
              ))}
            </div>
          </div>
        </div>

        {filtered.length === 0 ? (
          <EmptyState
            icon={<Globe size={22} />}
            title={sites.length === 0 ? "No protected sites configured" : "No sites match filter"}
            description={
              sites.length === 0
                ? "Add a host to route and inspect traffic, or pass WAFFYNX_SITE_HOST and WAFFYNX_SITE_UPSTREAM via Docker Compose."
                : "Clear your search or TLS filter to see all configured sites."
            }
            action={
              sites.length === 0 ? (
                <button type="button" className="btn btn-primary" onClick={openCreate}>
                  <Plus size={14} aria-hidden="true" />
                  <span>Add first site</span>
                </button>
              ) : undefined
            }
          />
        ) : (
          <div className="table-scroll" role="region" aria-label="Protected sites table" tabIndex={0}>
            <table className="data-table">
              <caption className="visually-hidden">
                Protected reverse-proxy sites: hostname, upstream, TLS status, path rules, plugins, and actions
              </caption>
              <thead>
                <tr>
                  <th scope="col">Hostname</th>
                  <th scope="col">Upstream</th>
                  <th scope="col">Transport</th>
                  <th scope="col">Paths</th>
                  <th scope="col">Plugins / Headers</th>
                  <th scope="col">Actions</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((site) => (
                  <tr key={site.host}>
                    <td>
                      <div style={{ display: "flex", alignItems: "center", gap: "0.45rem" }}>
                        <code className="mono" style={{ fontWeight: 700 }}>
                          {site.host}
                        </code>
                        {site.host.startsWith("*.") && <Badge variant="info">Wildcard</Badge>}
                      </div>
                    </td>
                    <td>
                      <span style={{ display: "inline-flex", alignItems: "center", gap: "0.35rem" }} className="mono text-secondary">
                        <Server size={13} aria-hidden="true" />
                        {site.upstream}
                      </span>
                    </td>
                    <td>
                      {site.tls ? (
                        <Badge variant="ok">
                          <Lock size={11} aria-hidden="true" />
                          HTTPS / TLS
                        </Badge>
                      ) : (
                        <Badge variant="high">
                          <Unlock size={11} aria-hidden="true" />
                          HTTP
                        </Badge>
                      )}
                    </td>
                    <td className="mono">{site.paths?.length ?? 0}</td>
                    <td>
                      <div style={{ display: "flex", gap: "0.3rem", flexWrap: "wrap" }}>
                        {(site.plugins ?? []).map((p) => (
                          <Badge key={p} variant="ml">
                            {p}
                          </Badge>
                        ))}
                        {Object.keys(site.headers ?? {}).length > 0 && (
                          <Badge variant="neutral">
                            {Object.keys(site.headers ?? {}).length} hdr
                          </Badge>
                        )}
                        {(site.plugins ?? []).length === 0 && Object.keys(site.headers ?? {}).length === 0 && (
                          <span className="text-muted">Default</span>
                        )}
                      </div>
                    </td>
                    <td>
                      <div style={{ display: "flex", gap: "0.4rem" }}>
                        <button
                          type="button"
                          className="btn btn-sm"
                          onClick={() => openEdit(site)}
                          aria-label={`Edit site ${site.host}`}
                        >
                          <Pencil size={13} aria-hidden="true" />
                          <span>Edit</span>
                        </button>
                        <button
                          type="button"
                          className="btn btn-danger btn-sm"
                          onClick={() => {
                            setPendingDelete(site);
                            setDeleteError("");
                          }}
                          aria-label={`Delete site ${site.host}`}
                        >
                          <Trash2 size={13} aria-hidden="true" />
                          <span>Delete</span>
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Create / Edit Site Drawer */}
      <Dialog
        open={editorOpen}
        onClose={() => setEditorOpen(false)}
        eyebrow={editingHost ? "Edit Reverse-Proxy Site" : "New Reverse-Proxy Site"}
        title={editingHost ?? "Add Protected Site"}
        variant="drawer"
        closedby="closerequest"
        footer={
          <>
            <button type="button" className="btn" onClick={() => setEditorOpen(false)} disabled={saving}>
              Cancel
            </button>
            <button
              type="submit"
              form="site-editor-form"
              className="btn btn-primary"
              disabled={saving}
              aria-busy={saving}
            >
              {saving ? "Validating nginx -t…" : editingHost ? "Save & Reload Nginx" : "Create & Reload Nginx"}
            </button>
          </>
        }
      >
        <div className="tablist" role="tablist" aria-label="Site configuration sections">
          {(
            [
              { id: "general", label: "General" },
              { id: "tls", label: "TLS / SSL" },
              { id: "paths", label: `Paths (${paths.length})` },
              { id: "plugins", label: "Plugins & Headers" },
              { id: "preview", label: "Nginx Preview" },
            ] as { id: EditorTab; label: string }[]
          ).map((t) => (
            <button
              key={t.id}
              type="button"
              role="tab"
              className="tab-item"
              aria-selected={editorTab === t.id}
              onClick={() => setEditorTab(t.id)}
            >
              {t.label}
            </button>
          ))}
        </div>

        {formError && (
          <div className="alert-banner error" role="alert">
            {formError}
          </div>
        )}

        <form id="site-editor-form" onSubmit={submitSite} noValidate style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
          {editorTab === "general" && (
            <>
              <div className="field">
                <label className="field-label" htmlFor="site-host-input">
                  Hostname (supports leading wildcard)
                </label>
                <span className="field-hint" id="site-host-hint">
                  Example: <code>app.example.com</code> or <code>*.api.example.com</code>. No scheme or port.
                </span>
                <input
                  id="site-host-input"
                  className={`input mono ${fieldErrors.host ? "user-invalid-fallback" : ""}`}
                  value={host}
                  onChange={(e) => setHost(e.target.value)}
                  disabled={Boolean(editingHost)}
                  placeholder="app.example.com"
                  autoComplete="off"
                  aria-invalid={Boolean(fieldErrors.host)}
                  aria-describedby={fieldErrors.host ? "site-host-hint site-host-err" : "site-host-hint"}
                  autoFocus={!editingHost}
                  required
                />
                {editingHost && (
                  <span className="field-hint">
                    Hostnames cannot be renamed in place; delete and recreate to change the server name.
                  </span>
                )}
                {fieldErrors.host && (
                  <p className="field-error" id="site-host-err">
                    {fieldErrors.host}
                  </p>
                )}
              </div>

              <div className="field">
                <label className="field-label" htmlFor="site-upstream-input">
                  Upstream Origin
                </label>
                <span className="field-hint" id="site-upstream-hint">
                  Explicit port required: <code>backend:80</code>, <code>10.0.0.5:8080</code>, or <code>https://origin:8443</code>.
                </span>
                <input
                  id="site-upstream-input"
                  className={`input mono ${fieldErrors.upstream ? "user-invalid-fallback" : ""}`}
                  value={upstream}
                  onChange={(e) => setUpstream(e.target.value)}
                  placeholder="backend:80"
                  autoComplete="off"
                  aria-invalid={Boolean(fieldErrors.upstream)}
                  aria-describedby={fieldErrors.upstream ? "site-upstream-hint site-upstream-err" : "site-upstream-hint"}
                  autoFocus={Boolean(editingHost)}
                  required
                />
                {fieldErrors.upstream && (
                  <p className="field-error" id="site-upstream-err">
                    {fieldErrors.upstream}
                  </p>
                )}
              </div>
            </>
          )}

          {editorTab === "tls" && (
            <>
              <div className="alert-banner info">
                Provide container-local certificate and key file paths (e.g. mounted inside <code>/opt/waffynx/certs/</code>). Both are required together.
              </div>
              <div className="field">
                <label className="field-label" htmlFor="site-cert-input">
                  Certificate File Path
                </label>
                <span className="field-hint">Example: /opt/waffynx/certs/server.crt</span>
                <input
                  id="site-cert-input"
                  className="input mono"
                  value={certFile}
                  onChange={(e) => setCertFile(e.target.value)}
                  placeholder="/opt/waffynx/certs/server.crt"
                  autoComplete="off"
                />
              </div>
              <div className="field">
                <label className="field-label" htmlFor="site-key-input">
                  Private Key File Path
                </label>
                <span className="field-hint">Example: /opt/waffynx/certs/server.key</span>
                <input
                  id="site-key-input"
                  className="input mono"
                  value={keyFile}
                  onChange={(e) => setKeyFile(e.target.value)}
                  placeholder="/opt/waffynx/certs/server.key"
                  autoComplete="off"
                />
              </div>
              {fieldErrors.tls && <p className="field-error">{fieldErrors.tls}</p>}
            </>
          )}

          {editorTab === "paths" && (
            <>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span className="field-hint">
                  Route specific path prefixes (e.g. <code>/api</code>) to an alternate upstream.
                </span>
                <button
                  type="button"
                  className="btn btn-sm"
                  onClick={() => setPaths((prev) => [...prev, { path: "/", upstream: "" }])}
                >
                  <Plus size={13} />
                  <span>Add path rule</span>
                </button>
              </div>

              {paths.length === 0 ? (
                <EmptyState
                  title="No path overrides"
                  description="All traffic for this host routes to the primary upstream."
                />
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: "0.55rem" }}>
                  {paths.map((row, idx) => (
                    <div key={idx} className="repeater-row">
                      <input
                        className="input mono"
                        aria-label={`Path prefix ${idx + 1}`}
                        placeholder="/api"
                        value={row.path}
                        onChange={(e) =>
                          setPaths((prev) =>
                            prev.map((item, i) => (i === idx ? { ...item, path: e.target.value } : item))
                          )
                        }
                      />
                      <input
                        className="input mono"
                        aria-label={`Path upstream ${idx + 1}`}
                        placeholder="api-svc:9000 (optional)"
                        value={row.upstream ?? ""}
                        onChange={(e) =>
                          setPaths((prev) =>
                            prev.map((item, i) => (i === idx ? { ...item, upstream: e.target.value } : item))
                          )
                        }
                      />
                      <button
                        type="button"
                        className="btn btn-danger btn-icon"
                        aria-label={`Remove path rule ${idx + 1}`}
                        onClick={() => setPaths((prev) => prev.filter((_, i) => i !== idx))}
                      >
                        <Trash2 size={14} />
                      </button>
                    </div>
                  ))}
                </div>
              )}
              {fieldErrors.paths && <p className="field-error">{fieldErrors.paths}</p>}
            </>
          )}

          {editorTab === "plugins" && (
            <>
              <div className="field">
                <span className="field-label">Attached Plugins</span>
                <span className="field-hint">Select registered inspection plugins to associate with this site.</span>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(190px, 1fr))", gap: "0.5rem", marginTop: "0.35rem" }}>
                  {plugins.map((pl) => (
                    <label
                      key={pl.name}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "0.5rem",
                        padding: "0.55rem 0.7rem",
                        borderRadius: "var(--radius-sm)",
                        border: "1px solid var(--border-subtle)",
                        background: "var(--surface-elevated)",
                        cursor: "pointer",
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={selectedPlugins.includes(pl.name)}
                        onChange={() => togglePlugin(pl.name)}
                      />
                      <span className="mono" style={{ fontSize: "0.8rem" }}>
                        {pl.name}
                      </span>
                    </label>
                  ))}
                </div>
              </div>

              <div className="field">
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <span className="field-label">Custom Response Headers</span>
                  <button
                    type="button"
                    className="btn btn-sm"
                    onClick={() => setHeaderRows((prev) => [...prev, { key: "", value: "" }])}
                  >
                    <Plus size={13} />
                    <span>Add header</span>
                  </button>
                </div>

                {headerRows.map((row, idx) => (
                  <div key={idx} className="repeater-row">
                    <input
                      className="input mono"
                      aria-label={`Header name ${idx + 1}`}
                      placeholder="X-Frame-Options"
                      value={row.key}
                      onChange={(e) =>
                        setHeaderRows((prev) =>
                          prev.map((item, i) => (i === idx ? { ...item, key: e.target.value } : item))
                        )
                      }
                    />
                    <input
                      className="input mono"
                      aria-label={`Header value ${idx + 1}`}
                      placeholder="DENY"
                      value={row.value}
                      onChange={(e) =>
                        setHeaderRows((prev) =>
                          prev.map((item, i) => (i === idx ? { ...item, value: e.target.value } : item))
                        )
                      }
                    />
                    <button
                      type="button"
                      className="btn btn-danger btn-icon"
                      aria-label={`Remove header ${idx + 1}`}
                      onClick={() => setHeaderRows((prev) => prev.filter((_, i) => i !== idx))}
                    >
                      <Trash2 size={14} />
                    </button>
                  </div>
                ))}
                {fieldErrors.headers && <p className="field-error">{fieldErrors.headers}</p>}
              </div>
            </>
          )}

          {editorTab === "preview" && (
            <>
              <div className="alert-banner info">
                Informational preview of the rendered Nginx server block. The control plane performs
                authoritative rendering and executes <code>nginx -t</code> before reload.
              </div>
              <CodeBlock label="Rendered Topology Preview" copyText={draftPreview}>
                {draftPreview}
              </CodeBlock>
            </>
          )}
        </form>
      </Dialog>

      <ConfirmDialog
        open={Boolean(pendingDelete)}
        onClose={() => setPendingDelete(null)}
        title={`Delete ${pendingDelete?.host ?? "site"}?`}
        description="The generated Nginx server block will be removed and Nginx reloaded. Incoming traffic for this hostname will receive HTTP 404."
        confirmLabel="Delete site"
        cancelLabel="Keep site"
        busy={deleting}
        error={deleteError}
        onConfirm={confirmDelete}
      />
    </div>
  );
};
