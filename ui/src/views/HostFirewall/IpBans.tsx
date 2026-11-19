import React, { useEffect, useMemo, useState } from "react";
import { Ban, Clock, Search, Shield, ShieldCheck, X } from "lucide-react";
import { useWaf } from "../../context/WafContext";
import { useToast } from "../../context/ToastContext";
import { ApiError } from "../../api/client";
import type { BannedIP } from "../../api/types";
import { KpiCard } from "../../components/common/KpiCard";
import { Badge } from "../../components/common/Badge";
import { EmptyState } from "../../components/common/EmptyState";
import { ConfirmDialog } from "../../components/common/ConfirmDialog";
import { formatCountdown, formatDateTime } from "../../utils/format";
import { isValidIP } from "../../utils/validators";

const TTL_PRESETS = [
  { label: "15m", seconds: 900 },
  { label: "1h", seconds: 3600 },
  { label: "24h", seconds: 86400 },
  { label: "7d", seconds: 604800 },
];

const REASON_PRESETS = [
  "SQLi probing",
  "Credential stuffing",
  "Automated scanner",
  "Rate limit abuse",
  "Manual SOC block",
];

export const IpBans: React.FC = () => {
  const { firewall, bannedIPs, banIP, unbanIP } = useWaf();
  const { pushToast } = useToast();

  const [ip, setIp] = useState("");
  const [reason, setReason] = useState("");
  const [ttl, setTtl] = useState("3600");
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);

  const [query, setQuery] = useState("");
  const [nowMs, setNowMs] = useState(() => Date.now());
  const [pendingUnban, setPendingUnban] = useState<BannedIP | null>(null);
  const [unbanning, setUnbanning] = useState(false);
  const [unbanError, setUnbanError] = useState("");

  // Live countdown ticker every second while bans exist
  useEffect(() => {
    if (bannedIPs.length === 0) return;
    const id = setInterval(() => setNowMs(Date.now()), 1000);
    return () => clearInterval(id);
  }, [bannedIPs.length]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return bannedIPs;
    return bannedIPs.filter(
      (b) => b.ip.toLowerCase().includes(q) || (b.reason || "").toLowerCase().includes(q)
    );
  }, [bannedIPs, query]);

  const submitBan = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    const trimmedIp = ip.trim();
    if (!trimmedIp) {
      setError("An IPv4 or IPv6 address is required.");
      return;
    }
    if (!isValidIP(trimmedIp)) {
      setError(`"${trimmedIp}" is not a valid IPv4 or IPv6 address.`);
      return;
    }

    const parsedTtl = Math.max(60, Math.floor(Number(ttl) || 3600));
    setSaving(true);
    try {
      await banIP(trimmedIp, reason.trim() || "Manual ban from Control Room", parsedTtl);
      pushToast("ok", `Banned ${trimmedIp}`, `Active for ${parsedTtl}s in the WAF sidecar.`);
      setIp("");
      setReason("");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not enforce IP ban.");
    } finally {
      setSaving(false);
    }
  };

  const confirmUnban = async () => {
    if (!pendingUnban) return;
    setUnbanning(true);
    setUnbanError("");
    try {
      await unbanIP(pendingUnban.ip);
      pushToast("info", `Lifted ban on ${pendingUnban.ip}`);
      setPendingUnban(null);
    } catch (err) {
      setUnbanError(err instanceof ApiError ? err.message : "Could not lift ban.");
    } finally {
      setUnbanning(false);
    }
  };

  return (
    <div className="canvas-inner">
      <header className="view-header">
        <div>
          <h1 className="view-title" id="view-heading" tabIndex={-1}>
            IP Access &amp; Firewall Bans
          </h1>
          <p className="view-subtitle">
            Every ban is injected as a Stage-1 custom rule inside the Go sidecar (works without
            host privileges in Docker). Kernel-level <code>nftables</code>/<code>ufw</code> drops
            activate only when running <code>waf-agent</code> in system mode.
          </p>
        </div>
      </header>

      <section className="kpi-grid">
        <KpiCard
          title="Active IP Bans"
          value={bannedIPs.length}
          subtext="Evaluated before managed rules & plugins"
          badge="Enforced"
          tone={bannedIPs.length > 0 ? "critical" : "info"}
        />
        <KpiCard
          title="WAF Layer (Sidecar)"
          value="Active"
          subtext="Privilege-free container-safe enforcement"
          badge="Primary"
          tone="ok"
        />
        <KpiCard
          title="Host Kernel Firewall"
          value={firewall.enabled ? firewall.backend : "Disabled"}
          subtext={
            firewall.enabled
              ? `Synced to host ${firewall.backend} drop chain`
              : "Container mode — kernel driver disabled"
          }
          badge={firewall.enabled ? "System Mode" : "Optional"}
          tone={firewall.enabled ? "ok" : "default"}
        />
      </section>

      {error && (
        <div className="alert-banner error" role="alert">
          {error}
        </div>
      )}

      {/* Quick Ban Form */}
      <section className="panel">
        <div className="panel-header">
          <div>
            <h2 className="panel-title">Ban Source IP Address</h2>
            <p className="panel-subtitle">
              Immediately rejects matching traffic with HTTP 403 until TTL expiration
            </p>
          </div>
        </div>
        <div className="panel-body">
          <form onSubmit={submitBan} noValidate style={{ display: "flex", flexDirection: "column", gap: "0.9rem" }}>
            <div className="form-grid-2">
              <div className="field">
                <label className="field-label" htmlFor="ban-ip-input">
                  IPv4 / IPv6 Address
                </label>
                <span className="field-hint">Single client IP (use Custom Rules for CIDR subnets)</span>
                <input
                  id="ban-ip-input"
                  className="input mono"
                  value={ip}
                  onChange={(e) => setIp(e.target.value)}
                  placeholder="203.0.113.9"
                  autoComplete="off"
                  required
                />
              </div>

              <div className="field">
                <label className="field-label" htmlFor="ban-ttl-input">
                  Duration (TTL seconds)
                </label>
                <div className="pill-group" role="group" aria-label="TTL presets">
                  {TTL_PRESETS.map((p) => (
                    <button
                      key={p.seconds}
                      type="button"
                      className="pill mono"
                      aria-pressed={Number(ttl) === p.seconds}
                      onClick={() => setTtl(String(p.seconds))}
                    >
                      {p.label}
                    </button>
                  ))}
                </div>
                <input
                  id="ban-ttl-input"
                  type="number"
                  min={60}
                  className="input mono"
                  value={ttl}
                  onChange={(e) => setTtl(e.target.value)}
                />
              </div>
            </div>

            <div className="field">
              <label className="field-label" htmlFor="ban-reason-input">
                Reason (recorded in audit log &amp; SSE feed)
              </label>
              <div className="pill-group" role="group" aria-label="Common ban reasons">
                {REASON_PRESETS.map((r) => (
                  <button
                    key={r}
                    type="button"
                    className="pill"
                    aria-pressed={reason === r}
                    onClick={() => setReason(r)}
                  >
                    {r}
                  </button>
                ))}
              </div>
              <input
                id="ban-reason-input"
                className="input"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                placeholder="Credential stuffing"
                autoComplete="off"
              />
            </div>

            <div>
              <button
                type="submit"
                className="btn btn-danger-solid"
                disabled={saving}
                aria-busy={saving}
              >
                <Ban size={15} aria-hidden="true" />
                <span>{saving ? "Applying ban…" : "Enforce IP Ban"}</span>
              </button>
            </div>
          </form>
        </div>
      </section>

      {/* Active Bans Table */}
      <section className="panel">
        <div className="filter-bar">
          <div className="filter-row">
            <div className="search-wrap">
              <Search size={15} className="search-wrap-icon" aria-hidden="true" />
              <label htmlFor="bans-search" className="visually-hidden">
                Search banned IPs
              </label>
              <input
                id="bans-search"
                type="search"
                className="search-input"
                placeholder="Filter banned addresses by IP or reason…"
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
            <span className="mono text-muted" style={{ fontSize: "0.78rem" }}>
              {filtered.length} of {bannedIPs.length} active
            </span>
          </div>
        </div>

        {filtered.length === 0 ? (
          <EmptyState
            icon={<Shield size={22} />}
            title={bannedIPs.length === 0 ? "No addresses currently banned" : "No bans match filter"}
            description={
              bannedIPs.length === 0
                ? "Banned IPs appear here with live TTL countdowns and can be lifted at any time."
                : "Clear the search filter to see all active IP bans."
            }
          />
        ) : (
          <div className="table-scroll" role="region" aria-label="Active IP bans" tabIndex={0}>
            <table className="data-table">
              <caption className="visually-hidden">
                Active IP bans: source IP, reason, remaining TTL, expiration time, and actions
              </caption>
              <thead>
                <tr>
                  <th scope="col">IP Address</th>
                  <th scope="col">Reason</th>
                  <th scope="col">Remaining</th>
                  <th scope="col">Expires At</th>
                  <th scope="col">Actions</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((ban) => {
                  const cd = formatCountdown(ban.expires_at, nowMs);
                  return (
                    <tr key={ban.ip}>
                      <td className="mono" style={{ fontWeight: 700 }}>
                        {ban.ip}
                      </td>
                      <td className="text-secondary">{ban.reason || "—"}</td>
                      <td>
                        <Badge variant={cd.expired ? "neutral" : "critical"}>
                          <Clock size={11} aria-hidden="true" />
                          <span className="mono">{cd.label}</span>
                        </Badge>
                      </td>
                      <td className="mono text-muted">{formatDateTime(ban.expires_at)}</td>
                      <td>
                        <button
                          type="button"
                          className="btn btn-sm"
                          onClick={() => {
                            setPendingUnban(ban);
                            setUnbanError("");
                          }}
                          aria-label={`Lift ban on ${ban.ip}`}
                        >
                          <ShieldCheck size={13} aria-hidden="true" />
                          <span>Lift ban</span>
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <ConfirmDialog
        open={Boolean(pendingUnban)}
        onClose={() => setPendingUnban(null)}
        title={`Lift ban on ${pendingUnban?.ip ?? ""}?`}
        description="Removes the IP ban rule from the WAF sidecar (and host firewall when enabled). Traffic from this address will be evaluated normally again."
        confirmLabel="Lift ban"
        cancelLabel="Keep banned"
        busy={unbanning}
        error={unbanError}
        onConfirm={confirmUnban}
      />
    </div>
  );
};
