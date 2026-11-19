import React from "react";
import { AlertTriangle } from "lucide-react";
import { Dialog } from "./Dialog";

interface ConfirmDialogProps {
  open: boolean;
  title: string;
  description: string;
  confirmLabel: string;
  cancelLabel?: string;
  busy?: boolean;
  error?: string;
  onConfirm: () => void | Promise<void>;
  onClose: () => void;
}

export const ConfirmDialog: React.FC<ConfirmDialogProps> = ({
  open,
  title,
  description,
  confirmLabel,
  cancelLabel = "Cancel",
  busy = false,
  error,
  onConfirm,
  onClose,
}) => (
  <Dialog
    open={open}
    onClose={onClose}
    title={title}
    eyebrow="Confirmation required"
    variant="modal"
    closedby="closerequest"
    footer={
      <>
        {/* Destructive confirmation: focus starts on the safe action. */}
        <button type="button" className="btn" onClick={onClose} autoFocus disabled={busy}>
          {cancelLabel}
        </button>
        <button
          type="button"
          className="btn btn-danger-solid"
          onClick={() => void onConfirm()}
          disabled={busy}
          aria-busy={busy}
        >
          {busy ? "Applying…" : confirmLabel}
        </button>
      </>
    }
  >
    <div style={{ display: "flex", gap: "0.75rem", alignItems: "flex-start" }}>
      <AlertTriangle size={20} color="var(--status-critical)" aria-hidden="true" style={{ marginTop: 2 }} />
      <p className="text-secondary" style={{ fontSize: "0.86rem" }}>
        {description}
      </p>
    </div>
    {error && (
      <div className="alert-banner error" role="alert">
        {error}
      </div>
    )}
  </Dialog>
);
