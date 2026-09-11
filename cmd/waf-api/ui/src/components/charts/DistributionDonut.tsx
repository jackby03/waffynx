import React from "react";

export interface DonutSegment {
  label: string;
  count: number;
  pct: number;
  color: string;
}

interface DistributionDonutProps {
  segments: DonutSegment[];
  total: number;
}

export const DistributionDonut: React.FC<DistributionDonutProps> = ({ segments, total }) => {
  const circumference = 100; // SVG dash units
  let accumulated = 0;

  return (
    <div className="donut-wrapper">
      <div className="donut-graphic">
        <svg viewBox="0 0 36 36" className="donut-svg">
          {/* Base track */}
          <circle
            cx="18"
            cy="18"
            r="15.915"
            fill="none"
            stroke="rgba(255, 255, 255, 0.05)"
            strokeWidth="3.2"
          />
          {segments.map((seg, idx) => {
            if (seg.pct <= 0) return null;
            const dashArray = `${(seg.pct / 100) * circumference} ${circumference}`;
            const dashOffset = -accumulated;
            accumulated += (seg.pct / 100) * circumference;

            return (
              <circle
                key={idx}
                cx="18"
                cy="18"
                r="15.915"
                fill="none"
                stroke={seg.color}
                strokeWidth="3.2"
                strokeDasharray={dashArray}
                strokeDashoffset={dashOffset}
                className="donut-segment"
              />
            );
          })}
        </svg>
        <div className="donut-center-label">
          <span className="donut-total-count">{total}</span>
          <span className="donut-total-sub">Incidents</span>
        </div>
      </div>

      <div className="donut-legend">
        {segments.map((seg, idx) => (
          <div key={idx} className="donut-legend-item">
            <span className="donut-legend-dot" style={{ backgroundColor: seg.color }} />
            <span className="donut-legend-name">{seg.label}</span>
            <span className="donut-legend-value">
              {seg.count} ({seg.pct}%)
            </span>
          </div>
        ))}
      </div>
    </div>
  );
};
