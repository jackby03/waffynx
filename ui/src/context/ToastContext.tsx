import React, { createContext, useCallback, useContext, useState } from "react";
import { AlertCircle, CheckCircle2, Info, TriangleAlert, X } from "lucide-react";

export type ToastTone = "ok" | "error" | "warn" | "info";

export interface ToastItem {
  id: number;
  tone: ToastTone;
  title: string;
  detail?: string;
}

interface ToastContextValue {
  pushToast: (tone: ToastTone, title: string, detail?: string) => void;
}

const ToastContext = createContext<ToastContextValue | undefined>(undefined);

let nextToastId = 1;

export const ToastProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const [politeAnnouncement, setPoliteAnnouncement] = useState("");
  const [assertiveAnnouncement, setAssertiveAnnouncement] = useState("");

  const dismiss = useCallback((id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const pushToast = useCallback(
    (tone: ToastTone, title: string, detail?: string) => {
      const id = nextToastId++;
      setToasts((prev) => [...prev.slice(-3), { id, tone, title, detail }]);

      const text = detail ? `${title}: ${detail}` : title;
      if (tone === "error") {
        setAssertiveAnnouncement("");
        requestAnimationFrame(() => setAssertiveAnnouncement(text));
      } else {
        setPoliteAnnouncement("");
        requestAnimationFrame(() => setPoliteAnnouncement(text));
      }

      setTimeout(() => {
        dismiss(id);
      }, tone === "error" ? 6500 : 4000);
    },
    [dismiss]
  );

  return (
    <ToastContext.Provider value={{ pushToast }}>
      {children}

      <div className="visually-hidden" aria-live="polite" aria-atomic="true">
        {politeAnnouncement}
      </div>
      <div className="visually-hidden" aria-live="assertive" aria-atomic="true">
        {assertiveAnnouncement}
      </div>

      {toasts.length > 0 && (
        <div className="toast-viewport">
          {toasts.map((t) => (
            <div key={t.id} className={`toast ${t.tone}`}>
              <span aria-hidden="true" style={{ marginTop: 1 }}>
                {t.tone === "ok" && <CheckCircle2 size={16} color="var(--status-ok)" />}
                {t.tone === "error" && <AlertCircle size={16} color="var(--status-critical)" />}
                {t.tone === "warn" && <TriangleAlert size={16} color="var(--status-high)" />}
                {t.tone === "info" && <Info size={16} color="var(--accent-primary)" />}
              </span>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontWeight: 650 }}>{t.title}</div>
                {t.detail && <div className="text-secondary" style={{ fontSize: "0.76rem", marginTop: 2 }}>{t.detail}</div>}
              </div>
              <button
                type="button"
                className="btn btn-ghost btn-icon"
                style={{ minWidth: 24, minHeight: 24 }}
                onClick={() => dismiss(t.id)}
                aria-label="Dismiss notification"
              >
                <X size={14} />
              </button>
            </div>
          ))}
        </div>
      )}
    </ToastContext.Provider>
  );
};

export function useToast(): ToastContextValue {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error("useToast must be used within ToastProvider");
  return ctx;
}
