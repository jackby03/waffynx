import React, { useCallback, useEffect, useMemo, useState } from "react";
import { CheckCircle2, Download, Search, Store, Trash2, X } from "lucide-react";
import { wafApi } from "../../api/wafApi";
import { ApiError } from "../../api/client";
import type { MarketplacePackage } from "../../api/types";
import { useToast } from "../../context/ToastContext";
import { KpiCard } from "../../components/common/KpiCard";
import { Badge } from "../../components/common/Badge";
import { EmptyState } from "../../components/common/EmptyState";

export const MarketplaceView: React.FC = () => {
  const { pushToast } = useToast();

  const [packages, setPackages] = useState<MarketplacePackage[]>([]);
  const [categories, setCategories] = useState<string[]>([]);
  const [selectedCategory, setSelectedCategory] = useState("all");
  const [statusFilter, setStatusFilter] = useState<"all" | "installed" | "published">("all");
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [busyPkg, setBusyPkg] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [pkgs, cats] = await Promise.all([
        wafApi.getMarketplace(),
        wafApi.getMarketplaceCategories(),
      ]);
      setPackages(pkgs);
      setCategories(["all", ...cats.sort()]);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not load marketplace catalog.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return packages.filter((pkg) => {
      if (selectedCategory !== "all" && pkg.category !== selectedCategory) return false;
      if (statusFilter !== "all" && pkg.status !== statusFilter) return false;
      if (!q) return true;
      return (
        pkg.name.toLowerCase().includes(q) ||
        pkg.description.toLowerCase().includes(q) ||
        (pkg.tags ?? []).some((t) => t.toLowerCase().includes(q))
      );
    });
  }, [packages, selectedCategory, statusFilter, query]);

  const installedCount = packages.filter((p) => p.status === "installed").length;

  const handleInstallToggle = async (pkg: MarketplacePackage) => {
    setBusyPkg(pkg.name);
    try {
      if (pkg.status === "installed") {
        await wafApi.uninstallMarketplacePackage(pkg.name);
        pushToast("info", `Uninstalled ${pkg.name}`);
      } else {
        await wafApi.installMarketplacePackage(pkg.name, pkg.version);
        pushToast("ok", `Installed ${pkg.name} v${pkg.version}`);
      }
      await load();
    } catch (err) {
      pushToast(
        "error",
        `Action failed for ${pkg.name}`,
        err instanceof ApiError ? err.message : "Marketplace request rejected"
      );
    } finally {
      setBusyPkg(null);
    }
  };

  return (
    <div className="canvas-inner">
      <header className="view-header">
        <div>
          <h1 className="view-title" id="view-heading" tabIndex={-1}>
            AppSec Marketplace
          </h1>
          <p className="view-subtitle">
            Discover, install, and manage Waffynx security packages served by{" "}
            <code>/api/v1/marketplace</code>.
          </p>
        </div>
      </header>

      {error && (
        <div className="alert-banner error" role="alert">
          <span>{error}</span>
          <button type="button" className="btn btn-sm" onClick={() => void load()}>
            Retry
          </button>
        </div>
      )}

      <section className="kpi-grid">
        <KpiCard title="Available Packages" value={packages.length} subtext="Verified Waffynx catalog" tone="info" />
        <KpiCard title="Installed" value={installedCount} subtext="Active in control-plane store" tone="ok" />
        <KpiCard title="Categories" value={Math.max(0, categories.length - 1)} subtext="Security & validation modules" tone="ml" />
      </section>

      <section className="panel">
        <div className="filter-bar">
          <div className="filter-row">
            <div className="search-wrap">
              <Search size={15} className="search-wrap-icon" aria-hidden="true" />
              <label htmlFor="mkt-search" className="visually-hidden">
                Search marketplace packages
              </label>
              <input
                id="mkt-search"
                type="search"
                className="search-input"
                placeholder="Search packages by name, description, or tag…"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
              />
              {query && (
                <button
                  type="button"
                  className="search-clear-btn"
                  onClick={() => setQuery("")}
                  aria-label="Clear search"
                >
                  <X size={13} />
                </button>
              )}
            </div>

            <div className="pill-group" role="group" aria-label="Filter by install status">
              {(["all", "installed", "published"] as const).map((st) => (
                <button
                  key={st}
                  type="button"
                  className="pill"
                  aria-pressed={statusFilter === st}
                  onClick={() => setStatusFilter(st)}
                >
                  {st === "all" ? "All" : st === "installed" ? "Installed" : "Available"}
                </button>
              ))}
            </div>
          </div>

          <div className="pill-group" role="group" aria-label="Filter by category">
            {categories.map((cat) => (
              <button
                key={cat}
                type="button"
                className="pill"
                aria-pressed={selectedCategory === cat}
                onClick={() => setSelectedCategory(cat)}
              >
                {cat}
              </button>
            ))}
          </div>
        </div>

        <div className="panel-body">
          {loading && packages.length === 0 ? (
            <div className="empty-state">
              <p className="empty-state-desc">Loading marketplace catalog…</p>
            </div>
          ) : filtered.length === 0 ? (
            <EmptyState
              icon={<Store size={22} />}
              title="No packages match filters"
              description="Try clearing the search query or selecting another category."
            />
          ) : (
            <div className="cards-grid">
              {filtered.map((pkg) => {
                const isInstalled = pkg.status === "installed";
                const isBusy = busyPkg === pkg.name;
                return (
                  <article key={`${pkg.name}-${pkg.version}`} className="feature-card">
                    <div className="feature-card-head">
                      <div>
                        <h3 className="mono" style={{ fontSize: "0.96rem", fontWeight: 700 }}>
                          {pkg.name}
                        </h3>
                        <div className="text-muted mono" style={{ fontSize: "0.73rem", marginTop: 2 }}>
                          v{pkg.version} · {pkg.author} · {pkg.license}
                        </div>
                      </div>
                      <Badge variant={isInstalled ? "ok" : "neutral"} dot={isInstalled}>
                        {isInstalled ? "Installed" : pkg.category}
                      </Badge>
                    </div>

                    <p className="text-secondary" style={{ fontSize: "0.82rem" }}>
                      {pkg.description}
                    </p>

                    <div style={{ display: "flex", gap: "0.3rem", flexWrap: "wrap" }}>
                      {(pkg.tags ?? []).map((t) => (
                        <span key={t} className="rule-chip">
                          #{t}
                        </span>
                      ))}
                    </div>

                    <div className="feature-card-foot">
                      <span className="text-muted" style={{ fontSize: "0.74rem", display: "inline-flex", alignItems: "center", gap: "0.3rem" }}>
                        {isInstalled && <CheckCircle2 size={13} color="var(--status-ok)" aria-hidden="true" />}
                        <span>{isInstalled ? "Installed in store" : "Ready to install"}</span>
                      </span>

                      <button
                        type="button"
                        className={isInstalled ? "btn btn-danger btn-sm" : "btn btn-primary btn-sm"}
                        disabled={isBusy}
                        aria-busy={isBusy}
                        onClick={() => void handleInstallToggle(pkg)}
                      >
                        {isInstalled ? (
                          <>
                            <Trash2 size={13} aria-hidden="true" />
                            <span>{isBusy ? "Removing…" : "Uninstall"}</span>
                          </>
                        ) : (
                          <>
                            <Download size={13} aria-hidden="true" />
                            <span>{isBusy ? "Installing…" : "Install"}</span>
                          </>
                        )}
                      </button>
                    </div>
                  </article>
                );
              })}
            </div>
          )}
        </div>
      </section>
    </div>
  );
};
