import React, { useCallback, useEffect, useState } from "react";
import { Brain, CheckCircle2, Plus, RefreshCw, Sparkles, TriangleAlert } from "lucide-react";
import { wafApi } from "../../api/wafApi";
import { ApiError } from "../../api/client";
import type { CustomRule, LearningStats, LearningSuggestion } from "../../api/types";
import { useWaf } from "../../context/WafContext";
import { useToast } from "../../context/ToastContext";
import { KpiCard } from "../../components/common/KpiCard";
import { Badge } from "../../components/common/Badge";
import { EmptyState } from "../../components/common/EmptyState";
import { CodeBlock } from "../../components/common/CodeBlock";
import { isValidIP } from "../../utils/validators";

export const LearningView: React.FC = () => {
  const { config, status, refreshConfig } = useWaf();
  const { pushToast } = useToast();

  const [stats, setStats] = useState<LearningStats | null>(null);
  const [suggestions, setSuggestions] = useState<LearningSuggestion[]>([]);
  const [loading, setLoading] = useState(true);
  const [sidecarError, setSidecarError] = useState("");
  const [toggling, setToggling] = useState(false);
  const [promotingPattern, setPromotingPattern] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setSidecarError("");
    try {
      const [st, sg] = await Promise.all([
        wafApi.getLearningStats(),
        wafApi.getLearningSuggestions(),
      ]);
      setStats(st);
      setSuggestions(sg);
    } catch (err) {
      setSidecarError(err instanceof ApiError ? err.message : "Sidecar learning engine unavailable.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const learningEnabled = Boolean(config?.appsec?.learning_mode);
  const appsecEnabled = Boolean(config?.appsec?.enabled ?? status?.config?.appsec_enabled);
  const engineName = config?.appsec?.engine ?? status?.config?.engine ?? "basic-go";

  const toggleLearningMode = async () => {
    setToggling(true);
    try {
      const next = !learningEnabled;
      await wafApi.updateConfig({ appsec: { learning_mode: next } });
      await refreshConfig();
      pushToast(
        "ok",
        `Learning mode ${next ? "enabled" : "disabled"}`,
        "Persisted to waffynx.yaml."
      );
    } catch (err) {
      pushToast(
        "error",
        "Failed to update learning mode",
        err instanceof ApiError ? err.message : "Update rejected"
      );
    } finally {
      setToggling(false);
    }
  };

  const promoteSuggestion = async (s: LearningSuggestion) => {
    setPromotingPattern(s.pattern);
    try {
      const isBlock = s.type === "blocklist" || s.type === "rate_limit";
      const rule: CustomRule = {
        id: "",
        name: `Learned ${s.type}: ${s.pattern}`,
        description: `${s.description} (${Math.round(s.confidence * 100)}% confidence, ${s.matches} matches)`,
        enabled: true,
        priority: 80,
        action: isBlock ? "block" : "allow",
        ...(isValidIP(s.pattern) ? { ips: [s.pattern] } : { path_pattern: s.pattern }),
      };
      const created = await wafApi.createCustomRule(rule);
      pushToast(
        "ok",
        `Promoted suggestion to rule ${created.id}`,
        "Now enforced live in the Go sidecar."
      );
    } catch (err) {
      pushToast(
        "error",
        "Could not promote suggestion",
        err instanceof ApiError ? err.message : "Sidecar rejected rule"
      );
    } finally {
      setPromotingPattern(null);
    }
  };

  const bufferPct =
    stats && stats.max > 0 ? Math.min(100, Math.round((stats.total / stats.max) * 100)) : 0;

  return (
    <div className="canvas-inner">
      <header className="view-header">
        <div>
          <h1 className="view-title" id="view-heading" tabIndex={-1}>
            Behavioral Learning &amp; AppSec
          </h1>
          <p className="view-subtitle">
            Observes verdicts in the Go sidecar to surface recurring patterns as actionable
            whitelist, blocklist, or rate-limit rule candidates.
          </p>
        </div>
        <div className="view-actions">
          <button type="button" className="btn btn-sm" onClick={() => void load()} disabled={loading}>
            <RefreshCw size={14} aria-hidden="true" />
            <span>Refresh</span>
          </button>
          <button
            type="button"
            className={learningEnabled ? "btn" : "btn btn-primary"}
            disabled={toggling}
            onClick={() => void toggleLearningMode()}
          >
            <Brain size={15} aria-hidden="true" />
            <span>{toggling ? "Saving…" : learningEnabled ? "Disable Learning Mode" : "Enable Learning Mode"}</span>
          </button>
        </div>
      </header>

      {sidecarError && (
        <div className="alert-banner warn" role="alert">
          <span className="alert-banner-content">
            <TriangleAlert size={16} aria-hidden="true" />
            <span>{sidecarError}</span>
          </span>
          <button type="button" className="btn btn-sm" onClick={() => void load()}>
            Retry
          </button>
        </div>
      )}

      <section className="kpi-grid">
        <KpiCard
          title="AppSec Scorer"
          value={engineName}
          subtext={appsecEnabled ? "Inline anomaly scoring enabled" : "Scorer disabled in config"}
          badge={appsecEnabled ? "Active" : "Off"}
          tone={appsecEnabled ? "ml" : "default"}
        />
        <KpiCard
          title="Recorded Verdicts"
          value={stats ? stats.total : "—"}
          subtext={stats ? `${bufferPct}% of ${stats.max} ring capacity` : "Awaiting sidecar telemetry"}
          badge="Learning Buffer"
          tone="info"
        />
        <KpiCard
          title="Allowed / Blocked"
          value={stats ? `${stats.allowed} / ${stats.blocked}` : "—"}
          subtext="Observed traffic ratio in learning buffer"
          tone="ok"
        />
        <KpiCard
          title="Rule Suggestions"
          value={suggestions.length}
          subtext="Ready to review or promote"
          badge={learningEnabled ? "Learning ON" : "Learning OFF"}
          tone={suggestions.length > 0 ? "ml" : "default"}
        />
      </section>

      <section className="panel">
        <div className="panel-header">
          <div>
            <h2 className="panel-title">Generated Policy Suggestions</h2>
            <p className="panel-subtitle">
              Derived directly from inspected traffic on the sidecar socket; never synthetic
            </p>
          </div>
          <Badge variant="ml">
            <Sparkles size={12} aria-hidden="true" />
            {suggestions.length} candidates
          </Badge>
        </div>
        <div className="panel-body">
          {loading && suggestions.length === 0 ? (
            <div className="empty-state">
              <p className="empty-state-desc">Loading suggestions from sidecar…</p>
            </div>
          ) : suggestions.length === 0 ? (
            <EmptyState
              icon={<CheckCircle2 size={22} />}
              title="No behavioral suggestions yet"
              description="As the sidecar observes repeated benign routes or recurring attack bursts, high-confidence rule candidates will appear here for one-click promotion."
            />
          ) : (
            <div className="cards-grid">
              {suggestions.map((s, idx) => {
                const confPct = Math.round(Math.max(0, Math.min(1, s.confidence)) * 100);
                const badgeVariant =
                  s.type === "blocklist"
                    ? "critical"
                    : s.type === "rate_limit"
                      ? "high"
                      : "ok";
                return (
                  <article key={`${s.type}-${s.pattern}-${idx}`} className="feature-card">
                    <div className="feature-card-head">
                      <div>
                        <Badge variant={badgeVariant}>{s.type.toUpperCase()}</Badge>
                        <h3 className="mono" style={{ fontSize: "0.92rem", marginTop: "0.45rem" }}>
                          {s.pattern}
                        </h3>
                      </div>
                      <span className="mono" style={{ fontWeight: 700, fontSize: "0.85rem" }}>
                        {confPct}%
                      </span>
                    </div>

                    <div className="confidence-bar" aria-label={`Confidence ${confPct}%`}>
                      <div className="confidence-fill" style={{ inlineSize: `${confPct}%` }} />
                    </div>

                    <p className="text-secondary" style={{ fontSize: "0.82rem" }}>
                      {s.description}
                    </p>

                    {s.sample && (
                      <CodeBlock label={`Sample (${s.matches} matches)`} copyText={s.sample}>
                        {s.sample}
                      </CodeBlock>
                    )}

                    <div className="feature-card-foot">
                      <span className="mono text-muted" style={{ fontSize: "0.75rem" }}>
                        {s.matches} matching request{s.matches === 1 ? "" : "s"}
                      </span>
                      <button
                        type="button"
                        className="btn btn-primary btn-sm"
                        disabled={promotingPattern === s.pattern}
                        onClick={() => void promoteSuggestion(s)}
                      >
                        <Plus size={13} aria-hidden="true" />
                        <span>
                          {promotingPattern === s.pattern ? "Promoting…" : "Promote to Custom Rule"}
                        </span>
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
