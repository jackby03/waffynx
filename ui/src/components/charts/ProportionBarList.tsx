import React from "react";

export interface ProportionItem {
  key: string;
  label: string;
  count: number;
  sublabel?: string;
}

interface ProportionBarListProps {
  items: ProportionItem[];
  total: number;
  tone?: "default" | "critical" | "high" | "ok" | "ml";
  onSelect?: (item: ProportionItem) => void;
  renderAction?: (item: ProportionItem) => React.ReactNode;
}

export const ProportionBarList: React.FC<ProportionBarListProps> = ({
  items,
  total,
  tone = "default",
  onSelect,
  renderAction,
}) => {
  const max = Math.max(1, ...items.map((i) => i.count));

  return (
    <ol className="prop-list">
      {items.map((item) => {
        const widthPct = Math.max(4, Math.round((item.count / max) * 100));
        const sharePct = total > 0 ? Math.round((item.count / total) * 100) : 0;

        return (
          <li key={item.key} className="prop-row">
            <div className="prop-head">
              {onSelect ? (
                <button
                  type="button"
                  className="btn-link prop-label"
                  onClick={() => onSelect(item)}
                  title={item.label}
                >
                  {item.label}
                </button>
              ) : (
                <span className="prop-label" title={item.label}>
                  {item.label}
                </span>
              )}
              <div className="prop-meta">
                {item.sublabel && <span className="text-muted" style={{ fontSize: "0.72rem" }}>{item.sublabel}</span>}
                <span className="mono tabular" style={{ fontWeight: 700, fontSize: "0.78rem" }}>
                  {item.count}
                </span>
                <span className="mono text-muted" style={{ fontSize: "0.72rem", minWidth: 34, textAlign: "end" }}>
                  {sharePct}%
                </span>
                {renderAction?.(item)}
              </div>
            </div>
            <div className="prop-track" aria-hidden="true">
              <div
                className={`prop-fill ${tone !== "default" ? tone : ""}`}
                style={{ inlineSize: `${widthPct}%` }}
              />
            </div>
          </li>
        );
      })}
    </ol>
  );
};
