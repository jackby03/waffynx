import React, { useMemo } from "react";

interface ThroughputChartProps {
  legitimateData: number[];
  blockedData: number[];
  width?: number;
  height?: number;
}

function computePoints(data: number[], w: number, h: number): { polyline: string; area: string } {
  if (!data.length) return { polyline: "", area: "" };

  const padding = 10;
  const innerW = w;
  const innerH = h - padding * 2;
  const max = Math.max(...data, 1);

  const coords = data.map((val, i) => {
    const x = (i / Math.max(data.length - 1, 1)) * innerW;
    const clampedVal = Math.max(0, val);
    const y = innerH + padding - (clampedVal / max) * innerH;
    return [Math.round(x * 10) / 10, Math.round(y * 10) / 10];
  });

  const polyline = coords.map(([x, y]) => `${x},${y}`).join(" ");
  const area = `M0,${h} L${coords.map(([x, y]) => `${x},${y}`).join(" L")} L${innerW},${h} Z`;

  return { polyline, area };
}

export const ThroughputChart: React.FC<ThroughputChartProps> = ({
  legitimateData,
  blockedData,
  width = 600,
  height = 160,
}) => {
  const legitPaths = useMemo(
    () => computePoints(legitimateData, width, height),
    [legitimateData, width, height]
  );
  const blockPaths = useMemo(
    () => computePoints(blockedData, width, height),
    [blockedData, width, height]
  );

  return (
    <div className="chart-container">
      <svg
        viewBox={`0 0 ${width} ${height}`}
        preserveAspectRatio="none"
        className="throughput-svg"
        aria-label="Throughput Activity Chart"
      >
        <defs>
          <linearGradient id="cyanGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#00f2fe" stopOpacity="0.3" />
            <stop offset="100%" stopColor="#00f2fe" stopOpacity="0.0" />
          </linearGradient>
          <linearGradient id="crimsonGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#ff0055" stopOpacity="0.4" />
            <stop offset="100%" stopColor="#ff0055" stopOpacity="0.0" />
          </linearGradient>
        </defs>

        {/* Horizontal grid lines */}
        {[0.25, 0.5, 0.75].map((ratio) => {
          const y = height * ratio;
          return (
            <line
              key={ratio}
              x1="0"
              y1={y}
              x2={width}
              y2={y}
              stroke="rgba(255, 255, 255, 0.05)"
              strokeDasharray="4 4"
            />
          );
        })}

        {/* Legitimate Traffic Area & Line */}
        {legitPaths.area && <path d={legitPaths.area} fill="url(#cyanGrad)" />}
        {legitPaths.polyline && (
          <polyline
            points={legitPaths.polyline}
            fill="none"
            stroke="#00f2fe"
            strokeWidth="2.5"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        )}

        {/* Blocked Threats Area & Line */}
        {blockPaths.area && <path d={blockPaths.area} fill="url(#crimsonGrad)" />}
        {blockPaths.polyline && (
          <polyline
            points={blockPaths.polyline}
            fill="none"
            stroke="#ff0055"
            strokeWidth="2.5"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        )}
      </svg>
    </div>
  );
};
