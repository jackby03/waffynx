import React, { useState } from "react";
import { Check, Copy } from "lucide-react";

interface CodeBlockProps {
  label?: string;
  copyText?: string;
  children: React.ReactNode;
}

export const CodeBlock: React.FC<CodeBlockProps> = ({ label, copyText, children }) => {
  const [state, setState] = useState<"idle" | "copied" | "error">("idle");

  const handleCopy = async () => {
    if (!copyText) return;
    try {
      await navigator.clipboard.writeText(copyText);
      setState("copied");
    } catch {
      setState("error");
    }
    setTimeout(() => setState("idle"), 2000);
  };

  return (
    <div className="code-block">
      {(label || copyText) && (
        <div className="code-block-bar">
          <span>{label ?? "Code"}</span>
          {copyText && (
            <button
              type="button"
              className="btn btn-ghost btn-sm"
              style={{ color: "#cbd5e1", minBlockSize: 24, padding: "0.1rem 0.45rem" }}
              onClick={() => void handleCopy()}
            >
              {state === "copied" ? <Check size={13} color="#34d399" /> : <Copy size={13} />}
              <span>{state === "copied" ? "Copied" : state === "error" ? "Failed" : "Copy"}</span>
            </button>
          )}
        </div>
      )}
      <pre>
        <code>{children}</code>
      </pre>
    </div>
  );
};
