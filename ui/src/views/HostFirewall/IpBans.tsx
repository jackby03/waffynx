import React, { useState } from "react";
import { useWaf } from "../../context/WafContext";
import { KpiCard } from "../../components/common/KpiCard";
import { EmptyState } from "../../components/common/EmptyState";
import { IconShield } from "../../components/common/Icons";
import { ApiError } from "../../api/client";
import { wafApi } from "../../api/wafApi";

// IpBans is the container-mode version of what used to be "Host Firewall".
//
// nftables and UFW are host-enforcement (system mode): the container has no
// NET_ADMIN, so claiming kernel drops here would be fiction. What does work
// everywhere is the WAF layer: a ban becomes a custom rule the sidecar evaluates
// on every request, and the API answers 503 when no layer could enforce it.
export const IpBans: React.FC = () => {
  const { bannedIPs, unbanIP, refreshAll } = useWaf();

  const [ip, setIp] = useState("");
  const [reason, setReason] = useState("");
  const [ttl, setTtl] = useState("3600");
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setError("");

    const value = ip.trim();
    if (!value) {
      setError("An IP address is required.");
      return;
    }

    setSaving(true);
    try {
      await wafApi.banIP(value, reason.trim() || "manual ban", 3600);
      setIp("");
      setReason("");
      await refreshAll();
    } catch (err) {
      // The API rejects invalid addresses and answers 503 when the ban could not
      // be enforced anywhere; both are worth showing verbatim.
      setError(err instanceof ApiError ? err.message : "Could not ban that address.");
    } finally {
      setSaving(false);
    }
  };

  const handleUnban = async (address: string) => {
    setBusy(address);
    setError("");
    try {
      await unbanIP(address);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not lift that ban.");
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="view-stack">
      <header className="view-header">
        <div>
          <h1 className="view-title">IP Bans</h1>
          <p className="view-subtitle">
            Enforced at the WAF layer: each ban becomes a custom rule the sidecar evaluates on
            every request. Kernel-level drops with nftables or UFW are system mode only and are
            never started inside the container.
          </p>
        </div>
      </header>

      <section className="kpi-grid">
        <KpiCard
          title="Active bans"
          value={bannedIPs.length}
          subtext="Evaluated before the plugin chain"
          badge="WAF layer"
          variant="info"
        />
        <KpiCard
          title="Enforcement"
          value="Sidecar"
          subtext="No privileges required"
          badge="Container mode"
          variant="success"
        />
        <KpiCard
          title="Kernel drop"
          value="System mode"
          subtext="waf-agent + nftables, never in the container"
          badge="Optional"
          variant="warning"
        />
      </section>

      {error && (
        <div className="alert alert-error" role="alert">
          {error}
        </div>
      )}

      <div className="table-card">
        <div className="table-card-header">
          <div>
            <h2 className="table-title">Ban an address</h2>
            <span className="table-subtitle">The API refuses addresses it cannot parse</span>
          </div>
        </div>

        <form className="inline-form" onSubmit={submit} noValidate>
          <div className="form-field">
            <label className="form-label" htmlFor="ban-ip">
              IP address
            </label>
            <input
              id="ban-ip"
              className="form-input"
              value={ip}
              onChange={(e) => setIp(e.target.value)}
              placeholder="203.0.113.9"
              autoComplete="off"
              aria-invalid={error ? true : false}
            />
          </div>
          <div className="form-field">
            <label className="form-label" htmlFor="ban-reason">
              Reason (optional)
            </label>
            <input
              id="ban-reason"
              className="form-input"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Credential stuffing"
              autoComplete="off"
            />
          </div>
          <div className="form-field form-field-narrow">
            <label className="form-label" htmlFor="ban-ttl">
              TTL (seconds)
            </label>
            <input
              id="ban-ttl"
              className="form-input"
              type="number"
              min={60}
              value={ttl}
              onChange={(e) => setTtl(e.target.value)}
            />
          </div>
          <button type="submit" className="btn-primary-danger" disabled={saving} aria-busy={saving}>
            {saving ? "Applying…" : "Ban address"}
          </button>
        </form>
      </div>

      <div className="table-card">
        <div className="table-card-header">
          <div>
            <h2 className="table-title">Banned addresses</h2>
            <span className="table-subtitle">
              {bannedIPs.length} active ban{bannedIPs.length === 1 ? "" : "s"}
            </span>
          </div>
        </div>

        {bannedIPs.length === 0 ? (
          <EmptyState
            icon={<IconShield size={28} />}
            title="No address is banned"
            description="Bans applied here are enforced by the sidecar, so they work without host privileges."
          />
        ) : (
          <div className="table-scroll" role="region" aria-label="Banned addresses" tabIndex={0}>
            <table className="waf-table">
              <caption className="sr-only">Banned addresses: IP, reason, expiry and actions</caption>
              <thead>
                <tr>
                  <th scope="col">IP</th>
                  <th scope="col">Reason</th>
                  <th scope="col">Expires</th>
                  <th scope="col">Actions</th>
                </tr>
              </thead>
              <tbody>
                {bannedIPs.map((ban) => (
                  <tr key={ban.ip}>
                    <td>
                      <code>{ban.ip}</code>
                    </td>
                    <td className="text-muted">{ban.reason || "—"}</td>
                    <td>{ban.expires_at ? new Date(ban.expires_at).toLocaleString() : "—"}</td>
                    <td>
                      <button
                        type="button"
                        className="btn-unban"
                        onClick={() => void handleUnban(ban.ip)}
                        disabled={busy === ban.ip}
                        aria-label={`Lift ban on ${ban.ip}`}
                      >
                        {busy === ban.ip ? "Lifting…" : "Unban"}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
