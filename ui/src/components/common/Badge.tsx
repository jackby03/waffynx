import React from "react";

export type BadgeVariant =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "ok"
  | "info"
  | "ml"
  | "neutral";

interface BadgeProps {
  variant?: BadgeVariant;
  dot?: boolean;
  children: React.ReactNode;
}

export const Badge: React.FC<BadgeProps> = ({ variant = "neutral", dot = false, children }) => (
  <span className={`badge ${variant !== "neutral" ? `badge-${variant}` : ""}`}>
    {dot && <span className="pulse-dot" aria-hidden="true" />}
    {children}
  </span>
);
