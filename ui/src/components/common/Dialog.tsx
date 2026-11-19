import React, { useEffect, useId, useRef } from "react";
import { X } from "lucide-react";

let supportsDisplayTransitionCache: boolean | undefined;

/**
 * Probes whether discrete `display` transitions actually hold visibility
 * (Firefox 129+ parses allow-discrete without transitioning display).
 */
function canTransitionDisplay(): boolean {
  if (supportsDisplayTransitionCache !== undefined) return supportsDisplayTransitionCache;
  if (typeof window === "undefined" || !window.CSS?.supports?.("transition-behavior", "allow-discrete") || !document.body) {
    return false;
  }
  const probe = document.createElement("div");
  probe.style.cssText = "transition: display 1s allow-discrete !important; display: block;";
  document.body.appendChild(probe);
  getComputedStyle(probe).display;
  probe.style.display = "none";
  supportsDisplayTransitionCache = getComputedStyle(probe).display === "block";
  probe.remove();
  return supportsDisplayTransitionCache;
}

function supportsTopLayerExit(): boolean {
  return typeof window !== "undefined" && Boolean(window.CSS?.supports?.("overlay", "auto")) && canTransitionDisplay();
}

export interface DialogProps {
  open: boolean;
  onClose: () => void;
  title: string;
  eyebrow?: string;
  variant?: "modal" | "drawer" | "nav-drawer" | "palette";
  closedby?: "any" | "closerequest" | "none";
  hideHeader?: boolean;
  footer?: React.ReactNode;
  children: React.ReactNode;
}

export const Dialog: React.FC<DialogProps> = ({
  open,
  onClose,
  title,
  eyebrow,
  variant = "modal",
  closedby = "any",
  hideHeader = false,
  footer,
  children,
}) => {
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  const closingRef = useRef(false);

  const requestAnimatedClose = async () => {
    const el = ref.current;
    if (!el || !el.open || closingRef.current) return;
    if (supportsTopLayerExit()) {
      el.close();
      return;
    }
    closingRef.current = true;
    el.setAttribute("data-closing", "");
    const animations = el.getAnimations?.({ subtree: true }) ?? [];
    if (animations.length > 0) {
      await Promise.race([
        Promise.allSettled(animations.map((a) => a.finished)),
        new Promise((r) => setTimeout(r, 400)),
      ]);
    }
    el.removeAttribute("data-closing");
    closingRef.current = false;
    if (el.open) el.close();
  };

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    if (open) {
      el.removeAttribute("data-closing");
      closingRef.current = false;
      if (!el.open) el.showModal();
    } else if (el.open) {
      el.close();
    }
  }, [open]);

  // Fallback light-dismiss when native closedBy is unavailable (e.g. Safari)
  // plus animated exit routing for native cancel events.
  useEffect(() => {
    const el = ref.current;
    if (!el) return;

    const handleCancel = (e: Event) => {
      if (closedby === "none") {
        e.preventDefault();
        return;
      }
      if (!supportsTopLayerExit()) {
        e.preventDefault();
        void requestAnimatedClose();
      }
    };

    const outside = (ev: PointerEvent): boolean => {
      const r = el.getBoundingClientRect();
      return ev.clientX < r.left || ev.clientX > r.right || ev.clientY < r.top || ev.clientY > r.bottom;
    };

    let pressedOutside = false;
    const onPointerDown = (ev: PointerEvent) => {
      pressedOutside = outside(ev);
    };
    const onPointerUp = (ev: PointerEvent) => {
      if (pressedOutside && outside(ev)) {
        void requestAnimatedClose();
      }
      pressedOutside = false;
    };

    el.addEventListener("cancel", handleCancel);
    const needsLightDismissFallback =
      closedby === "any" && typeof HTMLDialogElement !== "undefined" && !("closedBy" in HTMLDialogElement.prototype);

    if (needsLightDismissFallback) {
      el.addEventListener("pointerdown", onPointerDown);
      el.addEventListener("pointerup", onPointerUp);
    }

    return () => {
      el.removeEventListener("cancel", handleCancel);
      if (needsLightDismissFallback) {
        el.removeEventListener("pointerdown", onPointerDown);
        el.removeEventListener("pointerup", onPointerUp);
      }
    };
  }, [closedby]);

  const handleNativeClose = () => {
    const el = ref.current;
    if (el) el.returnValue = "";
    onClose();
  };

  const variantClass =
    variant === "drawer"
      ? "drawer-dialog"
      : variant === "nav-drawer"
        ? "nav-drawer-dialog"
        : variant === "palette"
          ? "palette-dialog"
          : "modal-dialog";

  return (
    <dialog
      ref={ref}
      className={variantClass}
      aria-labelledby={hideHeader ? undefined : titleId}
      aria-label={hideHeader ? title : undefined}
      onClose={handleNativeClose}
      {...({ closedby } as Record<string, string>)}
    >
      {!hideHeader && (
        <header className="dialog-header">
          <div style={{ minWidth: 0 }}>
            {eyebrow && <div className="dialog-eyebrow">{eyebrow}</div>}
            <h2 className="dialog-title" id={titleId}>
              {title}
            </h2>
          </div>
          <button
            type="button"
            className="btn btn-ghost btn-icon"
            onClick={() => void requestAnimatedClose()}
            aria-label={`Close ${title}`}
          >
            <X size={16} />
          </button>
        </header>
      )}

      <div className={hideHeader ? undefined : "dialog-body"}>{children}</div>

      {footer && <footer className="dialog-footer">{footer}</footer>}
    </dialog>
  );
};
