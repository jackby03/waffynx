import React from "react";
import { Badge, type BadgeVariant } from "./Badge";

export type KpiTone = "default" | "critical" | "high" | "info" | "ok" | "ml";

interface KpiCardProps {
  title: string;
  value: string | number;
  subtext?: string;
  badge?: string;
  badgeVariant?: BadgeVariant;
  tone?: KpiTone;
  sparkline?: React.ReactNode;
}

export const KpiCard: React.FC<KpiCardProps> = ({
  title,
  value,
  subtext,
  badge,
  badgeVariant,
  tone = "default",
  sparkline,
}) => {
  const resolvedBadgeVariant: BadgeVariant =
    badgeVariant ??
    (tone === "critical"
      ? "critical"
      : tone === "high"
        ? "high"
        : tone === "ok"
          ? "ok"
          : tone === "ml"
            ? "ml"
            : tone === "info"
              ? "info"
              : "neutral");

  return (
    <article className={`kpi-card ${tone !== "default" ? tone : ""}`}>
      <div className="kpi-top">
        <span className="kpi-label">{title}</span>
        {badge && <Badge variant={resolvedBadgeVariant}>{badge}</Badge>}
      </div>
      <div className="kpi-body">
        <div className="kpi-value">{value}</div>
        {sparkline}
      </div>
      {subtext && <div className="kpi-sub">{subtext}</div>}
    </article>
  );
};
