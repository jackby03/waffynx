import React, { useEffect, useRef, useState } from "react";
import type { Verdict, WafEvent } from "../../api/types";
import { Badge } from "../../components/common/Badge";
import type { BadgeVariant } from "../../components/common/Badge";
import { IconCheck, IconClose, IconCopy } from "../../components/common/Icons";

/**
 * Spanish label and colour for each verdict the console can show.
 *
 * The engine sends `type`, not `action`; the derivation itself lives in
 * api/events.ts. This table only names the result.
 */
export const ACTION_META: Record<Verdict, { label: string; variant: BadgeVariant }> = {
  deny: { label: "Denied", variant: "critical" },
  allow: { label: "Allowed", variant: "success" },
  challenge: { label: "Challenge", variant: "medium" },
  rate_limited: { label: "Rate limited", variant: "high" },
};

/** Invalid timestamps are copied verbatim rather than replaced by a fake date. */
function formatTimestamp(timestamp: string): string {
  const date = new Date(timestamp);
  return Number.isNaN(date.getTime()) ? timestamp || "—" : date.toLocaleString();
}

/** Field order mirrors the WafEvent contract so a copied event reads as the type. */
function toJson(event: WafEvent): string {
  return JSON.stringify(
    {
      type: event.type,
      timestamp: event.timestamp,
      method: event.method,
      path: event.path,
      remote_ip: event.remote_ip,
      rule_id: event.rule_id,
      reason: event.reason,
      payload: event.payload,
      action: event.action,
      matched_field: event.matched_field,
      matched_value: event.matched_value,
    },
    null,
    2
  );
}

type CopyState = "idle" | "copied" | "error";

interface DetailFieldProps {
  label: string;
  value: React.ReactNode;
  wide?: boolean;
}

const DetailField: React.FC<DetailFieldProps> = ({ label, value, wide = false }) => (
  <div className="drawer-cell" style={wide ? { gridColumn: "1 / -1" } : undefined}>
    <dt className="drawer-cell-label">{label}</dt>
    <dd className="drawer-cell-value">{value}</dd>
  </div>
);

interface EventDetailDialogProps {
  event: WafEvent | null;
  onClose: () => void;
}

export const EventDetailDialog: React.FC<EventDetailDialogProps> = ({ event, onClose }) => {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [copyState, setCopyState] = useState<CopyState>("idle");

  useEffect(() => {
    // showModal() provides the top layer, focus containment and Esc handling. An
    // overlay div would have to reimplement all three, and did it worse.
    const el = dialogRef.current;
    if (el && event && !el.open) el.showModal();

    // "Copied" belongs to one event; a panel reused for the next one would lie.
    setCopyState("idle");
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [event]);

  if (!event) return null;

  const meta = ACTION_META[event.action];

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(toJson(event));
      setCopyState("copied");
    } catch {
      // Denied permission and an insecure origin both land here; the button has
      // to say so instead of pretending.
      setCopyState("error");
    }
    if (timerRef.current) clearTimeout(timerRef.current);
    timerRef.current = setTimeout(() => setCopyState("idle"), 2500);
  };

  return (
    <dialog
      ref={dialogRef}
      className="modal"
      aria-labelledby="event-detail-title"
      onClose={onClose}
      {...{ closedby: "any" }}
    >
      <div className="modal-body">
        <header className="modal-header">
          <div>
            <span className="drawer-pretitle">DETALLE DEL EVENTO</span>
            <h2 className="modal-title" id="event-detail-title">
              {event.rule_id || "Event without a rule"}
            </h2>
          </div>
          <button
            type="button"
            className="drawer-close-btn"
            onClick={() => dialogRef.current?.close()}
            aria-label="Close detail"
          >
            <IconClose size={16} />
          </button>
        </header>

        <div
          className="drawer-banner"
          style={
            event.action === "allow"
              ? { background: "rgba(16, 185, 129, 0.08)", borderColor: "rgba(16, 185, 129, 0.25)" }
              : undefined
          }
        >
          <Badge variant={meta.variant} size="md">
            {meta.label}
          </Badge>
          <span className="drawer-banner-meta">{formatTimestamp(event.timestamp)}</span>
        </div>

        <dl className="drawer-grid">
          <DetailField label="Type" value={event.type || "—"} />
          <DetailField label="Action (derived from type)" value={meta.label} />
          <DetailField label="Timestamp" value={<code>{event.timestamp || "—"}</code>} />
          <DetailField label="Method" value={event.method || "—"} />
          <DetailField label="Source IP" value={<code>{event.remote_ip || "—"}</code>} />
          <DetailField label="Rule" value={<code>{event.rule_id || "—"}</code>} />
          <DetailField label="Path" value={<code>{event.path || "—"}</code>} wide />
          <DetailField label="Reason" value={event.reason || "—"} wide />
          <DetailField label="Payload" value={<code>{event.payload || "—"}</code>} wide />
          <DetailField
            label="Matched field · derived from reason"
            value={<code>{event.matched_field || "—"}</code>}
            wide
          />
          <DetailField
            label="Matched value · derived from reason"
            value={<code>{event.matched_value || "—"}</code>}
            wide
          />
        </dl>

        <p className="table-hint">
          "Matched field" and "matched value" are derived on the client from{" "}
          <code>reason</code>/<code>payload</code>: the engine does not send them.
        </p>

        <footer className="modal-actions">
          <button type="button" className="btn-secondary" onClick={() => void handleCopy()}>
            {copyState === "copied" ? <IconCheck size={14} /> : <IconCopy size={14} />}
            <span aria-live="polite">
              {copyState === "copied"
                ? "Copied"
                : copyState === "error"
                  ? "Could not copy"
                  : "Copy as JSON"}
            </span>
          </button>
          <button
            type="button"
            className="btn-secondary"
            onClick={() => dialogRef.current?.close()}
          >
            Cerrar
          </button>
        </footer>
      </div>
    </dialog>
  );
};
