import React, { useMemo, useState } from "react";
import { Ban, Check, Copy, ShieldCheck, ShieldOff, Terminal } from "lucide-react";
import type { Verdict, WafEvent } from "../../api/types";
import { Badge, type BadgeVariant } from "../../components/common/Badge";
import { Dialog } from "../../components/common/Dialog";
import { CodeBlock } from "../../components/common/CodeBlock";
import { useWaf } from "../../context/WafContext";
import { useToast } from "../../context/ToastContext";
import { ApiError } from "../../api/client";
import {
  classifyEventVector,
  detectPipelineStage,
  formatDateTime,
  VECTOR_LABELS,
  type PipelineStage,
} from "../../utils/format";
import { tokenizeHostilePayload } from "../../utils/payloadHighlight";
import { formatEventAsCurl, formatEventAsRawHttp } from "../../utils/exportData";

export const ACTION_META: Record<Verdict, { label: string; variant: BadgeVariant }> = {
  deny: { label: "Blocked", variant: "critical" },
  allow: { label: "Allowed", variant: "ok" },
  challenge: { label: "Challenge", variant: "medium" },
  rate_limited: { label: "Rate Limited", variant: "high" },
};

const PIPELINE_STEPS: { id: PipelineStage; num: string; label: string; sub: string }[] = [
  { id: "custom", num: "Stage 1", label: "Custom Rules", sub: "IP bans & L7 rules" },
  { id: "catalog", num: "Stage 2", label: "Managed Catalog", sub: "Aho-Corasick" },
  { id: "plugins", num: "Stage 3", label: "Plugin Chain", sub: "Bot / Rate / Schema" },
  { id: "scorer", num: "Stage 4", label: "AppSec Scorer", sub: "Anomaly & entropy" },
];

const TTL_PRESETS = [
  { label: "15m", seconds: 900 },
  { label: "1h", seconds: 3600 },
  { label: "24h", seconds: 86400 },
  { label: "7d", seconds: 604800 },
];

interface EventDetailDialogProps {
  event: WafEvent | null;
  onClose: () => void;
}

export const EventDetailDialog: React.FC<EventDetailDialogProps> = ({ event, onClose }) => {
  const { bannedIPs, sites, banIP, unbanIP, createExclusion } = useWaf();
  const { pushToast } = useToast();

  const [ttl, setTtl] = useState(3600);
  const [mitigating, setMitigating] = useState(false);
  const [creatingExclusion, setCreatingExclusion] = useState(false);
  const [exclusionCreated, setExclusionCreated] = useState(false);
  const [copiedKind, setCopiedKind] = useState<"json" | "curl" | null>(null);

  const isAlreadyBanned = useMemo(
    () => Boolean(event?.remote_ip && bannedIPs.some((b) => b.ip === event.remote_ip)),
    [event, bannedIPs]
  );

  const tokens = useMemo(
    () => tokenizeHostilePayload(event?.matched_value || event?.path || ""),
    [event]
  );

  const cleanPath = useMemo(() => {
    const raw = event?.path || "/";
    const idx = raw.indexOf("?");
    return idx >= 0 ? raw.slice(0, idx) : raw;
  }, [event]);

  const handleCreateExclusion = async () => {
    if (!event?.rule_id) return;
    setCreatingExclusion(true);
    try {
      await createExclusion({
        name: `Tune FP ${event.rule_id} on ${cleanPath}`,
        rule_id: event.rule_id,
        path_exact: cleanPath,
        reason: `Created from forensic event (${event.method || "GET"} ${cleanPath})`,
        enabled: true,
      });
      setExclusionCreated(true);
      pushToast(
        "ok",
        `Exclusion created for ${event.rule_id}`,
        `Hot-reloaded to Data Plane for ${cleanPath}.`
      );
    } catch (err) {
      pushToast(
        "error",
        "Could not create exclusion",
        err instanceof ApiError ? err.message : "Persistent Control Plane store required"
      );
    } finally {
      setCreatingExclusion(false);
    }
  };

  if (!event) return null;

  const meta = ACTION_META[event.action];
  const vector = classifyEventVector(event);
  const stage = detectPipelineStage(event);
  const stageOrder: PipelineStage[] = ["custom", "catalog", "plugins", "scorer"];
  const matchedIdx = stageOrder.indexOf(stage);
  const firstSiteHost = sites[0]?.host || "app.example.test";

  const rawHttp = formatEventAsRawHttp(event);
  const curlCmd = formatEventAsCurl(event, firstSiteHost);
  const rawJson = JSON.stringify(event, null, 2);

  const copyText = async (kind: "json" | "curl", text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedKind(kind);
      setTimeout(() => setCopiedKind(null), 2000);
    } catch {
      pushToast("error", "Clipboard access denied");
    }
  };

  const handleMitigate = async () => {
    if (!event.remote_ip) return;
    setMitigating(true);
    try {
      if (isAlreadyBanned) {
        await unbanIP(event.remote_ip);
        pushToast("info", `Lifted ban on ${event.remote_ip}`);
      } else {
        await banIP(
          event.remote_ip,
          `Forensic ban (${event.rule_id || vector})`,
          ttl
        );
        pushToast("ok", `Banned ${event.remote_ip}`, `Enforced in WAF sidecar for ${ttl}s.`);
      }
    } catch (err) {
      pushToast("error", "Mitigation failed", err instanceof ApiError ? err.message : "Could not update ban state");
    } finally {
      setMitigating(false);
    }
  };

  return (
    <Dialog
      open={Boolean(event)}
      onClose={onClose}
      eyebrow="Deep Packet Forensics"
      title={event.rule_id || "Security Event"}
      variant="drawer"
      closedby="any"
      footer={
        <>
          <button type="button" className="btn btn-sm" onClick={() => void copyText("curl", curlCmd)}>
            {copiedKind === "curl" ? <Check size={14} color="var(--status-ok)" /> : <Terminal size={14} />}
            <span>{copiedKind === "curl" ? "Copied cURL" : "Copy cURL"}</span>
          </button>
          <button type="button" className="btn btn-sm" onClick={() => void copyText("json", rawJson)}>
            {copiedKind === "json" ? <Check size={14} color="var(--status-ok)" /> : <Copy size={14} />}
            <span>{copiedKind === "json" ? "Copied JSON" : "Copy JSON"}</span>
          </button>
          <button type="button" className="btn" onClick={onClose}>
            Close
          </button>
        </>
      }
    >
      {/* Verdict Header Banner */}
      <div
        className={`alert-banner ${event.action === "allow" ? "ok" : event.action === "rate_limited" ? "warn" : "error"}`}
      >
        <div className="alert-banner-content">
          <Badge variant={meta.variant} dot>
            {meta.label}
          </Badge>
          <Badge variant="neutral">{VECTOR_LABELS[vector]}</Badge>
        </div>
        <span className="mono" style={{ fontSize: "0.75rem" }}>
          {formatDateTime(event.timestamp)}
        </span>
      </div>

      {/* 4-Stage Pipeline Trace */}
      <div>
        <div className="field-label" style={{ marginBottom: "0.45rem" }}>
          Inspection Pipeline Trace
        </div>
        <div className="pipeline-trace">
          {PIPELINE_STEPS.map((step, idx) => {
            const stateClass = idx === matchedIdx ? "matched" : idx < matchedIdx ? "passed" : "";
            return (
              <div key={step.id} className={`pipeline-step ${stateClass}`}>
                <span className="pipeline-step-num">{step.num}</span>
                <span className="pipeline-step-name">{step.label}</span>
                <span className="text-muted" style={{ fontSize: "0.7rem" }}>
                  {idx === matchedIdx ? "Matched here" : idx < matchedIdx ? "Passed" : step.sub}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Key Request Attributes */}
      <dl className="detail-grid">
        <div className="detail-cell">
          <dt>Source IP</dt>
          <dd className="mono">{event.remote_ip || "—"}</dd>
        </div>
        <div className="detail-cell">
          <dt>HTTP Method</dt>
          <dd>
            <span className={`method-chip ${(event.method || "").toLowerCase()}`}>
              {event.method || "—"}
            </span>
          </dd>
        </div>
        <div className="detail-cell">
          <dt>Wire Event Type</dt>
          <dd className="mono">{event.type || "—"}</dd>
        </div>
        <div className="detail-cell">
          <dt>Triggered Rule ID</dt>
          <dd className="mono">{event.rule_id || "—"}</dd>
        </div>
        <div className="detail-cell wide">
          <dt>Request URI</dt>
          <dd className="mono">{event.path || "—"}</dd>
        </div>
        <div className="detail-cell wide">
          <dt>Engine Reason</dt>
          <dd>{event.reason || "—"}</dd>
        </div>
      </dl>

      {/* Safe Highlighted Payload */}
      <div>
        <div className="field-label" style={{ marginBottom: "0.4rem" }}>
          Intercepted Payload / Matched Fragment
        </div>
        <CodeBlock label="Normalized payload (safe token highlight)" copyText={event.matched_value || event.path}>
          {tokens.length === 0
            ? "No payload fragment reported by the engine."
            : tokens.map((t, i) =>
                t.hostile ? (
                  <mark key={i} className="payload-mark">
                    {t.text}
                  </mark>
                ) : (
                  <React.Fragment key={i}>{t.text}</React.Fragment>
                )
              )}
        </CodeBlock>
      </div>

      {/* Reconstructed Raw HTTP */}
      <CodeBlock label="Reconstructed Request Summary" copyText={rawHttp}>
        {rawHttp}
      </CodeBlock>

      {/* False-Positive One-Click Exclusion Tuning */}
      {event.rule_id && event.action !== "allow" && (
        <div className="panel" style={{ background: "var(--surface-elevated)" }}>
          <div className="panel-body" style={{ display: "flex", flexDirection: "column", gap: "0.65rem" }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "0.5rem" }}>
              <div>
                <div className="field-label">False-Positive Tuning (Hot-Reload)</div>
                <div className="field-hint">
                  Waive rule <code className="mono">{event.rule_id}</code> on exact path{" "}
                  <code className="mono">{cleanPath}</code> and push immediately via Redis Pub/Sub.
                </div>
              </div>
              {exclusionCreated && <Badge variant="ok">Exclusion Active</Badge>}
            </div>
            <div>
              <button
                type="button"
                className="btn btn-sm"
                disabled={creatingExclusion || exclusionCreated}
                aria-busy={creatingExclusion}
                onClick={() => void handleCreateExclusion()}
              >
                <ShieldOff size={14} aria-hidden="true" />
                <span>
                  {exclusionCreated
                    ? "Exclusion active on Data Plane"
                    : creatingExclusion
                    ? "Publishing exclusion…"
                    : "Create Exclusion"}
                </span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Rapid SOC IP Mitigation */}
      {event.remote_ip && (
        <div className="panel" style={{ background: "var(--surface-elevated)" }}>
          <div className="panel-body" style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "0.5rem" }}>
              <div>
                <div className="field-label">Rapid Source Mitigation</div>
                <div className="field-hint">
                  Enforced immediately by the WAF sidecar for <code className="mono">{event.remote_ip}</code>.
                </div>
              </div>
              {isAlreadyBanned && <Badge variant="critical">Currently Banned</Badge>}
            </div>

            {!isAlreadyBanned && (
              <div className="pill-group" role="group" aria-label="Ban duration">
                {TTL_PRESETS.map((preset) => (
                  <button
                    key={preset.seconds}
                    type="button"
                    className="pill"
                    aria-pressed={ttl === preset.seconds}
                    onClick={() => setTtl(preset.seconds)}
                  >
                    TTL {preset.label}
                  </button>
                ))}
              </div>
            )}

            <div>
              <button
                type="button"
                className={isAlreadyBanned ? "btn" : "btn btn-danger-solid"}
                disabled={mitigating}
                aria-busy={mitigating}
                onClick={() => void handleMitigate()}
              >
                {isAlreadyBanned ? (
                  <>
                    <ShieldCheck size={15} aria-hidden="true" />
                    <span>{mitigating ? "Lifting ban…" : `Lift ban on ${event.remote_ip}`}</span>
                  </>
                ) : (
                  <>
                    <Ban size={15} aria-hidden="true" />
                    <span>{mitigating ? "Applying ban…" : `Ban ${event.remote_ip}`}</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </Dialog>
  );
};
