import React, { useEffect, useMemo, useRef, useState } from "react";
import { wafApi } from "../../api/wafApi";
import { ApiError } from "../../api/client";
import type { Site } from "../../api/types";
import { EmptyState } from "../../components/common/EmptyState";
import { IconClose, IconShield } from "../../components/common/Icons";

/** Validation messages keyed by field, so each input can own its error. */
type FieldErrors = Partial<Record<"host" | "upstream" | "tls", string>>;

// A hostname, optionally with a port. No scheme, no path: nginx `server_name`
// cannot express those, and the API rejects them anyway.
const HOST_RE = /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$/i;
// host:port or host — what `proxy_pass` accepts without a scheme.
const UPSTREAM_RE = /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$/i;

function validate(host: string, upstream: string, cert: string, key: string): FieldErrors {
  const errors: FieldErrors = {};

  if (!host.trim()) {
    errors.host = "A hostname is required, for example app.example.com.";
  } else if (!HOST_RE.test(host.trim())) {
    errors.host = "Use a bare hostname without scheme or path, for example app.example.com.";
  }

  if (!upstream.trim()) {
    errors.upstream = "An upstream is required, for example 10.0.0.5:8080.";
  } else if (!UPSTREAM_RE.test(upstream.trim())) {
    errors.upstream = "Use host:port without a scheme, for example backend:8080.";
  }

  if (Boolean(cert.trim()) !== Boolean(key.trim())) {
    errors.tls = "A certificate and its key must be provided together.";
  }

  return errors;
}

export const SitesView: React.FC = () => {
  const [sites, setSites] = useState<Site[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState("");
  const [query, setQuery] = useState("");

  const [host, setHost] = useState("");
  const [upstream, setUpstream] = useState("");
  const [cert, setCert] = useState("");
  const [key, setKey] = useState("");
  const [fieldErrors, setFieldErrors] = useState<FieldErrors>({});
  const [formError, setFormError] = useState("");
  const [saving, setSaving] = useState(false);

  const [pendingDelete, setPendingDelete] = useState<Site | null>(null);
  const [deleteError, setDeleteError] = useState("");
  const [deleting, setDeleting] = useState(false);

  const createDialog = useRef<HTMLDialogElement>(null);
  const deleteDialog = useRef<HTMLDialogElement>(null);

  const load = async () => {
    setLoading(true);
    setLoadError("");
    try {
      setSites(await wafApi.listSites());
    } catch (err) {
      // No mock fallback: an invented topology is worse than an error.
      setLoadError(err instanceof ApiError ? err.message : "Could not load sites.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return sites;
    return sites.filter(
      (s) => s.host.toLowerCase().includes(q) || s.upstream.toLowerCase().includes(q)
    );
  }, [sites, query]);

  const openCreate = () => {
    setHost("");
    setUpstream("");
    setCert("");
    setKey("");
    setFieldErrors({});
    setFormError("");
    createDialog.current?.showModal();
  };

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setFormError("");

    const errors = validate(host, upstream, cert, key);
    setFieldErrors(errors);
    if (Object.keys(errors).length > 0) return;

    const site: Site = {
      host: host.trim().toLowerCase(),
      upstream: upstream.trim(),
    };
    if (cert.trim() && key.trim()) {
      site.tls = { cert_file: cert.trim(), key_file: key.trim() };
    }

    setSaving(true);
    try {
      await wafApi.createSite(site);
      createDialog.current?.close();
      await load();
    } catch (err) {
      // The API validates the same fields and rejects duplicates: its message is
      // more specific than anything the client can infer.
      setFormError(err instanceof ApiError ? err.message : "Could not create the site.");
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
      deleteDialog.current?.close();
      setPendingDelete(null);
      await load();
    } catch (err) {
      setDeleteError(err instanceof ApiError ? err.message : "Could not delete the site.");
    } finally {
      setDeleting(false);
    }
  };

  return (
    <section className="view-stack" aria-labelledby="sites-title">
      <header className="view-header">
        <div>
          <h1 className="view-title" id="sites-title">
            Sites
          </h1>
          <p className="view-subtitle">
            Reverse-proxy topology. Every change is validated with <code>nginx -t</code> before it
            is applied, and rolled back if nginx rejects it.
          </p>
        </div>
        <button type="button" className="btn-secondary" onClick={openCreate}>
          + Add site
        </button>
      </header>

      {loadError && (
        <div className="alert alert-error" role="alert">
          {loadError}{" "}
          <button type="button" className="btn-link" onClick={() => void load()}>
            Retry
          </button>
        </div>
      )}

      <div className="table-card">
        <div className="table-card-header">
          <div>
            <h2 className="table-title">Protected hosts</h2>
            <span className="table-subtitle">
              {sites.length} site{sites.length === 1 ? "" : "s"}
            </span>
          </div>
          <label className="form-label sr-only" htmlFor="site-search">
            Filter sites
          </label>
          <input
            id="site-search"
            type="search"
            className="form-input search-input"
            placeholder="Filter by host or upstream"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>

        {loading ? (
          <p className="table-hint" role="status">
            Loading sites…
          </p>
        ) : filtered.length === 0 ? (
          <EmptyState
            icon={<IconShield size={28} />}
            title={sites.length === 0 ? "No sites yet" : "No site matches that filter"}
            description={
              sites.length === 0
                ? "Add the first host to start protecting traffic. You can also set WAFFYNX_SITE_HOST and WAFFYNX_SITE_UPSTREAM at boot."
                : "Clear the filter to see every site again."
            }
          />
        ) : (
          <div
            className="table-scroll"
            role="region"
            aria-label="Protected sites"
            tabIndex={0}
          >
            <table className="waf-table">
              <caption className="sr-only">
                Protected sites: hostname, upstream, TLS status and path rules
              </caption>
              <thead>
                <tr>
                  <th scope="col">Hostname</th>
                  <th scope="col">Upstream</th>
                  <th scope="col">TLS</th>
                  <th scope="col">Path rules</th>
                  <th scope="col">Actions</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((site) => (
                  <tr key={site.host}>
                    <td>
                      <code>{site.host}</code>
                    </td>
                    <td>
                      <code className="text-muted">{site.upstream}</code>
                    </td>
                    <td>
                      {site.tls ? (
                        <span className="badge badge-ok">enabled</span>
                      ) : (
                        <span className="badge">plain HTTP</span>
                      )}
                    </td>
                    <td>{site.paths?.length ?? 0}</td>
                    <td>
                      <button
                        type="button"
                        className="btn-unban"
                        onClick={() => {
                          setPendingDelete(site);
                          setDeleteError("");
                          deleteDialog.current?.showModal();
                        }}
                        aria-label={`Delete site ${site.host}`}
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Add site */}
      <dialog
        ref={createDialog}
        className="modal"
        aria-labelledby="add-site-title"
        onClose={() => createDialog.current?.close()}
        {...{ closedby: "any" }}
      >
        <form className="modal-body" onSubmit={submit} noValidate>
          <header className="modal-header">
            <h2 className="modal-title" id="add-site-title">
              Add site
            </h2>
            <button
              type="button"
              className="drawer-close-btn"
              onClick={() => createDialog.current?.close()}
              aria-label="Close"
            >
              <IconClose size={16} />
            </button>
          </header>

          {formError && (
            <div className="alert alert-error" role="alert" id="site-form-error">
              {formError}
            </div>
          )}

          <div className="form-field">
            <label className="form-label" htmlFor="site-host">
              Hostname
            </label>
            <input
              id="site-host"
              className="form-input"
              value={host}
              onChange={(e) => setHost(e.target.value)}
              placeholder="app.example.com"
              autoComplete="off"
              aria-invalid={fieldErrors.host ? true : false}
              aria-describedby={fieldErrors.host ? "site-host-error" : undefined}
              autoFocus
              required
            />
            {fieldErrors.host && (
              <p className="field-error" id="site-host-error">
                {fieldErrors.host}
              </p>
            )}
          </div>

          <div className="form-field">
            <label className="form-label" htmlFor="site-upstream">
              Upstream
            </label>
            <input
              id="site-upstream"
              className="form-input"
              value={upstream}
              onChange={(e) => setUpstream(e.target.value)}
              placeholder="backend:8080"
              autoComplete="off"
              aria-invalid={fieldErrors.upstream ? true : false}
              aria-describedby={fieldErrors.upstream ? "site-upstream-error" : undefined}
              required
            />
            {fieldErrors.upstream && (
              <p className="field-error" id="site-upstream-error">
                {fieldErrors.upstream}
              </p>
            )}
          </div>

          <fieldset className="form-field">
            <legend className="form-label">TLS (optional)</legend>
            <label className="form-label" htmlFor="site-cert">
              Certificate path
            </label>
            <input
              id="site-cert"
              className="form-input"
              value={cert}
              onChange={(e) => setCert(e.target.value)}
              placeholder="/opt/waffynx/certs/app.crt"
              autoComplete="off"
              aria-invalid={fieldErrors.tls ? true : false}
              aria-describedby={fieldErrors.tls ? "site-tls-error" : undefined}
            />
            <label className="form-label" htmlFor="site-key">
              Key path
            </label>
            <input
              id="site-key"
              className="form-input"
              value={key}
              onChange={(e) => setKey(e.target.value)}
              placeholder="/opt/waffynx/certs/app.key"
              autoComplete="off"
              aria-invalid={fieldErrors.tls ? true : false}
              aria-describedby={fieldErrors.tls ? "site-tls-error" : undefined}
            />
            {fieldErrors.tls && (
              <p className="field-error" id="site-tls-error">
                {fieldErrors.tls}
              </p>
            )}
          </fieldset>

          <footer className="modal-actions">
            <button
              type="button"
              className="btn-secondary"
              onClick={() => createDialog.current?.close()}
            >
              Cancel
            </button>
            <button type="submit" className="btn-primary-danger" disabled={saving} aria-busy={saving}>
              {saving ? "Applying…" : "Add site"}
            </button>
          </footer>
        </form>
      </dialog>

      {/* Delete confirmation */}
      <dialog
        ref={deleteDialog}
        className="modal"
        aria-labelledby="delete-site-title"
        {...{ closedby: "closerequest" }}
      >
        <div className="modal-body">
          <h2 className="modal-title" id="delete-site-title">
            Delete {pendingDelete?.host}?
          </h2>
          <p className="view-subtitle">
            The nginx fragment is removed and nginx is reloaded. Traffic for this host will stop
            being proxied.
          </p>
          {deleteError && (
            <div className="alert alert-error" role="alert">
              {deleteError}
            </div>
          )}
          <footer className="modal-actions">
            {/* Destructive confirmation: focus starts on the safe action. */}
            <button
              type="button"
              className="btn-secondary"
              onClick={() => deleteDialog.current?.close()}
              autoFocus
            >
              Keep site
            </button>
            <button
              type="button"
              className="btn-primary-danger"
              onClick={() => void confirmDelete()}
              disabled={deleting}
              aria-busy={deleting}
            >
              {deleting ? "Deleting…" : "Delete site"}
            </button>
          </footer>
        </div>
      </dialog>
    </section>
  );
};
