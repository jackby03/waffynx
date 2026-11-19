import React from "react";

interface EmptyStateProps {
  icon?: React.ReactNode;
  title: string;
  description: string;
  action?: React.ReactNode;
}

export const EmptyState: React.FC<EmptyStateProps> = ({ icon, title, description, action }) => (
  <div className="empty-state">
    {icon && (
      <div className="empty-state-icon" aria-hidden="true">
        {icon}
      </div>
    )}
    <h3 className="empty-state-title">{title}</h3>
    <p className="empty-state-desc">{description}</p>
    {action && <div style={{ marginTop: "0.45rem" }}>{action}</div>}
  </div>
);
