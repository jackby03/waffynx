import React, { useCallback, useEffect, useMemo, useState } from "react";
import { Plus, RefreshCw, Sliders, Trash2, TriangleAlert } from "lucide-react";
import { wafApi } from "../../api/wafApi";
import { ApiError } from "../../api/client";
import type { CustomRule, CustomRuleAction } from "../../api/types";
import { useToast } from "../../context/ToastContext";
import { KpiCard } from "../../components/common/KpiCard";
import { Badge } from "../../components/common/Badge";
import { EmptyState } from "../../components/common/EmptyState";
import { Dialog } from "../../components/common/Dialog";
import { ConfirmDialog } from "../../components/common/ConfirmDialog";
import { CodeBlock } from "../../components/common/CodeBlock";
import { isValidCIDR, isValidIP } from "../../utils/validators";

const HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

function splitCsv(raw: string): string[] {
  return raw
    .split(/[,\n]/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function formatRuleExpression(rule: Partial<CustomRule>): string {
  const clauses: string[] = [];
  if (rule.methods && rule.methods.length > 0) {
    clauses.push(`http.request.method in {${rule.methods.map((m) => `"${m}"`).join(" ")}}`);
  }
  if (rule.hosts && rule.hosts.length > 0) {
    clauses.push(`http.host in {${rule.hosts.map((h) => `"${h}"`).join(" ")}}`);
  }
  if (rule.path_exact) {
    clauses.push(`http.request.uri.path eq "${rule.path_exact}"`);
  }
  if (rule.path_pattern) {
    clauses.push(`http.request.uri.path glob "${rule.path_pattern}"`);
  }
  if (rule.ips && rule.ips.length > 0) {
    clauses.push(`ip.src in {${rule.ips.join(" ")}}`);
  }
  if (rule.ip_cidrs && rule.ip_cidrs.length > 0) {
    clauses.push(`ip.src in {${rule.ip_cidrs.join(" ")}}`);
  }
  if (rule.header_name) {
    clauses.push(
      rule.header_value
        ? `http.request.headers["${rule.header_name}"] eq "${rule.header_value}"`
        : `exists(http.request.headers["${rule.header_name}"])`
    );
  }
  if (rule.query_param) {
    clauses.push(
      rule.query_value
        ? `http.request.uri.args["${rule.query_param}"] eq "${rule.query_value}"`
        : `exists(http.request.uri.args["${rule.query_param}"])`
    );
  }
  if (rule.body_contains) {
    clauses.push(`http.request.body contains "${rule.body_contains}"`);
  }

  const expr = clauses.length > 0 ? `(${clauses.join(" and ")})` : "(any request)";
  return `${expr} => ${(rule.action ?? "block").toUpperCase()}`;
}

export const CustomRulesView: React.FC = () => {
  const { pushToast } = useToast();

  const [rules, setRules] = useState<CustomRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [builderOpen, setBuilderOpen] = useState(false);

  // Builder form fields
  const [name, setName] = useState("");
  const [ruleId, setRuleId] = useState("");
  const [description, setDescription] = useState("");
  const [action, setAction] = useState<CustomRuleAction>("block");
  const [priority, setPriority] = useState("100");
  const [enabled, setEnabled] = useState(true);
  const [methods, setMethods] = useState<string[]>([]);
  const [hostsRaw, setHostsRaw] = useState("");
  const [pathExact, setPathExact] = useState("");
  const [pathPattern, setPathPattern] = useState("");
  const [ipsRaw, setIpsRaw] = useState("");
  const [cidrsRaw, setCidrsRaw] = useState("");
  const [headerName, setHeaderName] = useState("");
  const [headerValue, setHeaderValue] = useState("");
  const [queryParam, setQueryParam] = useState("");
  const [queryValue, setQueryValue] = useState("");
  const [bodyContains, setBodyContains] = useState("");
  const [formError, setFormError] = useState("");
  const [saving, setSaving] = useState(false);

  // Delete confirmation
  const [pendingDelete, setPendingDelete] = useState<CustomRule | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const list = await wafApi.getCustomRules();
      setRules(list);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not reach sidecar custom rules engine.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const resetBuilder = () => {
    setName("");
    setRuleId("");
    setDescription("");
    setAction("block");
    setPriority("100");
    setEnabled(true);
    setMethods([]);
    setHostsRaw("");
    setPathExact("");
    setPathPattern("");
    setIpsRaw("");
    setCidrsRaw("");
    setHeaderName("");
    setHeaderValue("");
    setQueryParam("");
    setQueryValue("");
    setBodyContains("");
    setFormError("");
    setBuilderOpen(true);
  };

  const draftRule = useMemo<CustomRule>(() => {
    const r: CustomRule = {
      id: ruleId.trim(),
      name: name.trim(),
      description: description.trim() || undefined,
      enabled,
      priority: Number(priority) || 100,
      action,
    };
    if (methods.length > 0) r.methods = methods;
    const hosts = splitCsv(hostsRaw);
    if (hosts.length > 0) r.hosts = hosts;
    if (pathExact.trim()) r.path_exact = pathExact.trim();
    if (pathPattern.trim()) r.path_pattern = pathPattern.trim();
    const ips = splitCsv(ipsRaw);
    if (ips.length > 0) r.ips = ips;
    const cidrs = splitCsv(cidrsRaw);
    if (cidrs.length > 0) r.ip_cidrs = cidrs;
    if (headerName.trim()) r.header_name = headerName.trim();
    if (headerValue.trim()) r.header_value = headerValue.trim();
    if (queryParam.trim()) r.query_param = queryParam.trim();
    if (queryValue.trim()) r.query_value = queryValue.trim();
    if (bodyContains.trim()) r.body_contains = bodyContains.trim();
    return r;
  }, [
    ruleId,
    name,
    description,
    enabled,
    priority,
    action,
    methods,
    hostsRaw,
    pathExact,
    pathPattern,
    ipsRaw,
    cidrsRaw,
    headerName,
    headerValue,
    queryParam,
    queryValue,
    bodyContains,
  ]);

  const previewExpression = useMemo(() => formatRuleExpression(draftRule), [draftRule]);

  const submitRule = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError("");

    if (!draftRule.name) {
      setFormError("Rule name is required.");
      return;
    }
    for (const ip of draftRule.ips ?? []) {
      if (!isValidIP(ip)) {
        setFormError(`Invalid IP address: "${ip}".`);
        return;
      }
    }
    for (const cidr of draftRule.ip_cidrs ?? []) {
      if (!isValidCIDR(cidr)) {
        setFormError(`Invalid CIDR range: "${cidr}" (expected e.g. 203.0.113.0/24).`);
        return;
      }
    }

    setSaving(true);
    try {
      const created = await wafApi.createCustomRule(draftRule);
      pushToast("ok", `Custom rule "${created.name || created.id}" deployed`, "Enforced live by the Go sidecar.");
      setBuilderOpen(false);
      await load();
    } catch (err) {
      setFormError(err instanceof ApiError ? err.message : "Sidecar rejected the rule.");
    } finally {
      setSaving(false);
    }
  };

  const confirmDelete = async () => {
    if (!pendingDelete) return;
    setDeleting(true);
    setDeleteError("");
    try {
      await wafApi.deleteCustomRule(pendingDelete.id);
      pushToast("info", `Deleted rule ${pendingDelete.id}`);
      setPendingDelete(null);
      await load();
    } catch (err) {
      setDeleteError(err instanceof ApiError ? err.message : "Could not delete rule.");
    } finally {
      setDeleting(false);
    }
  };

  const toggleMethod = (m: string) => {
    setMethods((prev) => (prev.includes(m) ? prev.filter((x) => x !== m) : [...prev, m]));
  };

  const ipBanCount = rules.filter((r) => r.id.startsWith("ip-ban-")).length;
  const operatorCount = rules.length - ipBanCount;

  return (
    <div className="canvas-inner">
      <header className="view-header">
        <div>
          <h1 className="view-title" id="view-heading" tabIndex={-1}>
            Custom WAF Rules
          </h1>
          <p className="view-subtitle">
            Dynamic Layer-7 rules proxied directly to the Go sidecar over the Unix socket. Evaluated
            in Stage 1 before the managed catalog and plugin chain.
          </p>
        </div>
        <div className="view-actions">
          <button type="button" className="btn btn-sm" onClick={() => void load()} disabled={loading}>
            <RefreshCw size={14} aria-hidden="true" />
            <span>Refresh</span>
          </button>
          <button type="button" className="btn btn-primary" onClick={resetBuilder}>
            <Plus size={15} aria-hidden="true" />
            <span>Create Custom Rule</span>
          </button>
        </div>
      </header>

      {error && (
        <div className="alert-banner warn" role="alert">
          <span className="alert-banner-content">
            <TriangleAlert size={16} aria-hidden="true" />
            <span>{error}</span>
          </span>
          <button type="button" className="btn btn-sm" onClick={() => void load()}>
            Retry
          </button>
        </div>
      )}

      <section className="kpi-grid">
        <KpiCard title="Active Sidecar Rules" value={rules.length} subtext="Live in data plane memory" tone="info" />
        <KpiCard title="Operator Policies" value={operatorCount} subtext="Custom L7 expressions" tone="ml" />
        <KpiCard title="IP Ban Rules" value={ipBanCount} subtext="Injected by IP Access & Bans" tone="critical" />
      </section>

      <section className="panel">
        <div className="panel-header">
          <div>
            <h2 className="panel-title">Enforced Custom Rules</h2>
            <p className="panel-subtitle">First matching enabled rule determines the request verdict</p>
          </div>
        </div>

        {loading && rules.length === 0 ? (
          <div className="empty-state">
            <p className="empty-state-desc">Querying sidecar rule engine…</p>
          </div>
        ) : rules.length === 0 ? (
          <EmptyState
            icon={<Sliders size={22} />}
            title="No custom rules deployed"
            description="Build rules matching HTTP methods, paths, hosts, IPs/CIDRs, headers, query parameters, or request bodies."
            action={
              <button type="button" className="btn btn-primary" onClick={resetBuilder}>
                <Plus size={14} />
                <span>Create first custom rule</span>
              </button>
            }
          />
        ) : (
          <div className="table-scroll" role="region" aria-label="Custom WAF rules table" tabIndex={0}>
            <table className="data-table">
              <caption className="visually-hidden">Custom WAF rules enforced by the sidecar</caption>
              <thead>
                <tr>
                  <th scope="col">ID</th>
                  <th scope="col">Name</th>
                  <th scope="col">Action</th>
                  <th scope="col">Expression</th>
                  <th scope="col">Priority</th>
                  <th scope="col">Actions</th>
                </tr>
              </thead>
              <tbody>
                {rules.map((rule) => (
                  <tr key={rule.id}>
                    <td>
                      <span className="rule-chip">{rule.id}</span>
                    </td>
                    <td>
                      <div style={{ fontWeight: 600 }}>{rule.name || "Unnamed rule"}</div>
                      {rule.description && (
                        <div className="text-muted" style={{ fontSize: "0.75rem" }}>
                          {rule.description}
                        </div>
                      )}
                    </td>
                    <td>
                      <Badge
                        variant={
                          rule.action === "block" || rule.action === "deny"
                            ? "critical"
                            : rule.action === "allow"
                              ? "ok"
                              : "high"
                        }
                      >
                        {rule.action.toUpperCase()}
                      </Badge>
                    </td>
                    <td className="mono cell-truncate" title={formatRuleExpression(rule)}>
                      {formatRuleExpression(rule)}
                    </td>
                    <td className="mono">{rule.priority}</td>
                    <td>
                      <button
                        type="button"
                        className="btn btn-danger btn-sm"
                        onClick={() => {
                          setPendingDelete(rule);
                          setDeleteError("");
                        }}
                        aria-label={`Delete custom rule ${rule.id}`}
                      >
                        <Trash2 size={13} aria-hidden="true" />
                        <span>Delete</span>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Visual Custom Rule Builder Drawer */}
      <Dialog
        open={builderOpen}
        onClose={() => setBuilderOpen(false)}
        eyebrow="Sidecar L7 Policy Builder"
        title="Create Custom WAF Rule"
        variant="drawer"
        closedby="closerequest"
        footer={
          <>
            <button type="button" className="btn" onClick={() => setBuilderOpen(false)} disabled={saving}>
              Cancel
            </button>
            <button
              type="submit"
              form="custom-rule-form"
              className="btn btn-primary"
              disabled={saving}
              aria-busy={saving}
            >
              {saving ? "Deploying to sidecar…" : "Deploy Rule"}
            </button>
          </>
        }
      >
        <CodeBlock label="Live Expression Preview" copyText={previewExpression}>
          {previewExpression}
        </CodeBlock>

        {formError && (
          <div className="alert-banner error" role="alert">
            {formError}
          </div>
        )}

        <form id="custom-rule-form" onSubmit={submitRule} noValidate style={{ display: "flex", flexDirection: "column", gap: "0.95rem" }}>
          <div className="form-grid-2">
            <div className="field">
              <label className="field-label" htmlFor="cr-name">
                Rule Name
              </label>
              <input
                id="cr-name"
                className="input"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Protect admin login"
                autoFocus
                required
              />
            </div>

            <div className="field">
              <label className="field-label" htmlFor="cr-id">
                Rule ID (optional)
              </label>
              <input
                id="cr-id"
                className="input mono"
                value={ruleId}
                onChange={(e) => setRuleId(e.target.value)}
                placeholder="custom-admin-lock"
              />
            </div>
          </div>

          <div className="form-grid-2">
            <div className="field">
              <label className="field-label" htmlFor="cr-action">
                Verdict Action
              </label>
              <select
                id="cr-action"
                className="select"
                value={action}
                onChange={(e) => setAction(e.target.value as CustomRuleAction)}
              >
                <option value="block">Block (403 Forbidden)</option>
                <option value="allow">Allow (Bypass remaining rules)</option>
                <option value="log">Log Only</option>
              </select>
            </div>

            <div className="field">
              <label className="field-label" htmlFor="cr-priority">
                Priority
              </label>
              <input
                id="cr-priority"
                type="number"
                className="input mono"
                value={priority}
                onChange={(e) => setPriority(e.target.value)}
              />
            </div>
          </div>

          <div className="field">
            <label className="field-label" htmlFor="cr-desc">
              Description (optional)
            </label>
            <input
              id="cr-desc"
              className="input"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Explain why this policy exists for SOC operators"
            />
          </div>

          <div className="field">
            <span className="field-label">HTTP Methods</span>
            <div className="pill-group" role="group" aria-label="HTTP methods">
              {HTTP_METHODS.map((m) => (
                <button
                  key={m}
                  type="button"
                  className="pill mono"
                  aria-pressed={methods.includes(m)}
                  onClick={() => toggleMethod(m)}
                >
                  {m}
                </button>
              ))}
            </div>
          </div>

          <div className="form-grid-2">
            <div className="field">
              <label className="field-label" htmlFor="cr-path-exact">
                Exact Path
              </label>
              <input
                id="cr-path-exact"
                className="input mono"
                value={pathExact}
                onChange={(e) => setPathExact(e.target.value)}
                placeholder="/wp-login.php"
              />
            </div>
            <div className="field">
              <label className="field-label" htmlFor="cr-path-glob">
                Path Glob Pattern
              </label>
              <input
                id="cr-path-glob"
                className="input mono"
                value={pathPattern}
                onChange={(e) => setPathPattern(e.target.value)}
                placeholder="/admin/*"
              />
            </div>
          </div>

          <div className="field">
            <label className="field-label" htmlFor="cr-hosts">
              Hosts (comma-separated)
            </label>
            <input
              id="cr-hosts"
              className="input mono"
              value={hostsRaw}
              onChange={(e) => setHostsRaw(e.target.value)}
              placeholder="app.example.com, api.example.com"
            />
          </div>

          <div className="form-grid-2">
            <div className="field">
              <label className="field-label" htmlFor="cr-ips">
                Source IPs (comma-separated)
              </label>
              <input
                id="cr-ips"
                className="input mono"
                value={ipsRaw}
                onChange={(e) => setIpsRaw(e.target.value)}
                placeholder="203.0.113.9, 198.51.100.4"
              />
            </div>
            <div className="field">
              <label className="field-label" htmlFor="cr-cidrs">
                Source CIDRs (comma-separated)
              </label>
              <input
                id="cr-cidrs"
                className="input mono"
                value={cidrsRaw}
                onChange={(e) => setCidrsRaw(e.target.value)}
                placeholder="203.0.113.0/24"
              />
            </div>
          </div>

          <div className="form-grid-2">
            <div className="field">
              <label className="field-label" htmlFor="cr-hdr-name">
                Header Name
              </label>
              <input
                id="cr-hdr-name"
                className="input mono"
                value={headerName}
                onChange={(e) => setHeaderName(e.target.value)}
                placeholder="User-Agent"
              />
            </div>
            <div className="field">
              <label className="field-label" htmlFor="cr-hdr-val">
                Header Value (optional)
              </label>
              <input
                id="cr-hdr-val"
                className="input mono"
                value={headerValue}
                onChange={(e) => setHeaderValue(e.target.value)}
                placeholder="BadBot/1.0"
              />
            </div>
          </div>

          <div className="form-grid-2">
            <div className="field">
              <label className="field-label" htmlFor="cr-qp">
                Query Parameter
              </label>
              <input
                id="cr-qp"
                className="input mono"
                value={queryParam}
                onChange={(e) => setQueryParam(e.target.value)}
                placeholder="debug"
              />
            </div>
            <div className="field">
              <label className="field-label" htmlFor="cr-qv">
                Query Value (optional)
              </label>
              <input
                id="cr-qv"
                className="input mono"
                value={queryValue}
                onChange={(e) => setQueryValue(e.target.value)}
                placeholder="true"
              />
            </div>
          </div>

          <div className="field">
            <label className="field-label" htmlFor="cr-body">
              Body Contains Substring
            </label>
            <input
              id="cr-body"
              className="input mono"
              value={bodyContains}
              onChange={(e) => setBodyContains(e.target.value)}
              placeholder="malicious_token"
            />
          </div>

          <label style={{ display: "inline-flex", alignItems: "center", gap: "0.5rem", cursor: "pointer" }}>
            <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
            <span className="field-label">Enable rule immediately upon deployment</span>
          </label>
        </form>
      </Dialog>

      <ConfirmDialog
        open={Boolean(pendingDelete)}
        onClose={() => setPendingDelete(null)}
        title={`Delete custom rule ${pendingDelete?.id ?? ""}?`}
        description="The rule will be removed immediately from the Go sidecar evaluation pipeline."
        confirmLabel="Delete rule"
        cancelLabel="Keep rule"
        busy={deleting}
        error={deleteError}
        onConfirm={confirmDelete}
      />
    </div>
  );
};
