import React, { useState } from "react";
import type { TimeBucket } from "../../utils/format";

interface TimeSeriesChartProps {
  buckets: TimeBucket[];
  caption: string;
  accentColor?: string;
}

export const TimeSeriesChart: React.FC<TimeSeriesChartProps> = ({
  buckets,
  caption,
  accentColor = "var(--status-critical)",
}) => {
  const [activeIndex, setActiveIndex] = useState<number | null>(null);

  const width = 880;
  const height = 210;
  const padLeft = 38;
  const padRight = 14;
  const padTop = 16;
  const padBottom = 28;
  const innerW = width - padLeft - padRight;
  const innerH = height - padTop - padBottom;

  const peak = Math.max(1, ...buckets.map((b) => b.count));
  const yMax = peak <= 4 ? 4 : Math.ceil(peak / 4) * 4;
  const yTicks = [0, yMax * 0.25, yMax * 0.5, yMax * 0.75, yMax];

  const step = innerW / Math.max(1, buckets.length);
  const barWidth = Math.max(4, Math.min(20, step * 0.62));
  const labelInterval = buckets.length > 40 ? 10 : buckets.length > 20 ? 5 : 3;

  const activeBucket = activeIndex !== null ? buckets[activeIndex] : null;
  const totalInWindow = buckets.reduce((sum, b) => sum + b.count, 0);

  return (
    <figure className="chart-figure">
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: "0.75rem",
          flexWrap: "wrap",
          fontSize: "0.78rem",
        }}
      >
        <figcaption className="text-secondary">{caption}</figcaption>
        <span className="mono text-secondary" aria-live="polite">
          {activeBucket
            ? `${activeBucket.label} · ${activeBucket.count} block${activeBucket.count === 1 ? "" : "s"}`
            : `Total: ${totalInWindow} · Peak: ${peak}/min`}
        </span>
      </div>

      <svg
        className="chart-svg"
        viewBox={`0 0 ${width} ${height}`}
        role="img"
        aria-label={`${caption}. Total ${totalInWindow}, peak ${peak} per minute.`}
      >
        {/* Horizontal gridlines & Y-axis ticks */}
        {yTicks.map((tick) => {
          const y = padTop + innerH - (tick / yMax) * innerH;
          return (
            <g key={tick}>
              <line
                x1={padLeft}
                x2={width - padRight}
                y1={y}
                y2={y}
                stroke="var(--border-subtle)"
                strokeDasharray={tick === 0 ? undefined : "3 4"}
              />
              <text
                x={padLeft - 8}
                y={y + 3.5}
                textAnchor="end"
                fontSize="10"
                fontFamily="var(--font-mono)"
                fill="var(--text-muted)"
              >
                {Math.round(tick)}
              </text>
            </g>
          );
        })}

        {/* Bars & interactive hit targets */}
        {buckets.map((bucket, idx) => {
          const cx = padLeft + idx * step + step / 2;
          const barH = bucket.count > 0 ? Math.max(3, (bucket.count / yMax) * innerH) : 0;
          const y = padTop + innerH - barH;
          const isHovered = activeIndex === idx;
          const showLabel = idx === 0 || idx === buckets.length - 1 || idx % labelInterval === 0;

          return (
            <g
              key={bucket.minute}
              onMouseEnter={() => setActiveIndex(idx)}
              onMouseLeave={() => setActiveIndex(null)}
            >
              <rect
                x={padLeft + idx * step}
                y={padTop}
                width={step}
                height={innerH}
                fill={isHovered ? "var(--accent-primary)" : "transparent"}
                fillOpacity={isHovered ? 0.08 : 0}
              />
              {bucket.count > 0 && (
                <rect
                  x={cx - barWidth / 2}
                  y={y}
                  width={barWidth}
                  height={barH}
                  rx={3}
                  fill={accentColor}
                  fillOpacity={isHovered ? 1 : 0.82}
                />
              )}
              {showLabel && (
                <text
                  x={cx}
                  y={height - 8}
                  textAnchor="middle"
                  fontSize="10"
                  fontFamily="var(--font-mono)"
                  fill={isHovered ? "var(--text-primary)" : "var(--text-muted)"}
                >
                  {bucket.label}
                </text>
              )}
            </g>
          );
        })}
      </svg>

      {/* Accessible tabular alternative for assistive technology */}
      <table className="visually-hidden">
        <caption>{caption}</caption>
        <thead>
          <tr>
            <th scope="col">Minute</th>
            <th scope="col">Blocked requests</th>
          </tr>
        </thead>
        <tbody>
          {buckets
            .filter((b) => b.count > 0)
            .map((b) => (
              <tr key={b.minute}>
                <td>{b.label}</td>
                <td>{b.count}</td>
              </tr>
            ))}
        </tbody>
      </table>
    </figure>
  );
};
