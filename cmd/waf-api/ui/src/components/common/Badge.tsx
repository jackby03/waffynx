import React from "react";

export type BadgeVariant = "critical" | "high" | "medium" | "low" | "success" | "info" | "neutral";

interface BadgeProps {
  children: React.ReactNode;
  variant?: BadgeVariant;
  size?: "sm" | "md";
}

export const Badge: React.FC<BadgeProps> = ({ children, variant = "neutral", size = "sm" }) => {
  return <span className={`waf-badge badge-${variant} badge-${size}`}>{children}</span>;
};
