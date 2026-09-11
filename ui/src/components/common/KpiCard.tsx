import React from "react";

interface KpiCardProps {
  title: string;
  value: React.ReactNode;
  subtext?: string;
  badge?: string;
  variant?: "default" | "critical" | "warning" | "success" | "info";
}

export const KpiCard: React.FC<KpiCardProps> = ({
  title,
  value,
  subtext,
  badge,
  variant = "default",
}) => {
  return (
    <article className={`kpi-card ${variant}`}>
      <div className="kpi-accent-glow" />
      <div className="kpi-header">
        <span>{title}</span>
        {badge && <span className="kpi-badge">{badge}</span>}
      </div>
      <div className="kpi-value">{value}</div>
      {subtext && <div className="kpi-subtext">{subtext}</div>}
    </article>
  );
};
