import React from "react";

export interface IconProps extends React.SVGProps<SVGSVGElement> {
  size?: number | string;
  color?: string;
  className?: string;
}

const defaultProps = {
  width: 18,
  height: 18,
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 2,
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
};

// 1. Threat Radar / Global Network Icon
export const IconGlobe: React.FC<IconProps> = ({ size = 18, color, className, ...props }) => (
  <svg
    {...defaultProps}
    width={size}
    height={size}
    stroke={color || "currentColor"}
    className={`waf-icon ${className || ""}`}
    {...props}
  >
    <circle cx="12" cy="12" r="10" />
    <path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20" />
    <path d="M2 12h20" />
  </svg>
);

// 2. Forensics / Deep Packet Inspection Icon
export const IconSearch: React.FC<IconProps> = ({ size = 18, color, className, ...props }) => (
  <svg
    {...defaultProps}
    width={size}
    height={size}
    stroke={color || "currentColor"}
    className={`waf-icon ${className || ""}`}
    {...props}
  >
    <circle cx="11" cy="11" r="8" />
    <path d="m21 21-4.35-4.35" />
  </svg>
);

// 3. Bot Defense Icon
export const IconBot: React.FC<IconProps> = ({ size = 18, color, className, ...props }) => (
  <svg
    {...defaultProps}
    width={size}
    height={size}
    stroke={color || "currentColor"}
    className={`waf-icon ${className || ""}`}
    {...props}
  >
    <rect x="3" y="11" width="18" height="10" rx="2" />
    <circle cx="12" cy="5" r="2" />
    <path d="M12 7v4" />
    <line x1="8" y1="16" x2="8" y2="16" strokeWidth={3} />
    <line x1="16" y1="16" x2="16" y2="16" strokeWidth={3} />
  </svg>
);

// 4. Reverse Proxy / Traffic Director Icon
export const IconArrows: React.FC<IconProps> = ({ size = 18, color, className, ...props }) => (
  <svg
    {...defaultProps}
    width={size}
    height={size}
    stroke={color || "currentColor"}
    className={`waf-icon ${className || ""}`}
    {...props}
  >
    <path d="m16 3 4 4-4 4" />
    <path d="M20 7H4" />
    <path d="m8 21-4-4 4-4" />
    <path d="M4 17h16" />
  </svg>
);

// 5. Security Policies / Shield Icon
export const IconShield: React.FC<IconProps> = ({ size = 18, color, className, ...props }) => (
  <svg
    {...defaultProps}
    width={size}
    height={size}
    stroke={color || "currentColor"}
    className={`waf-icon ${className || ""}`}
    {...props}
  >
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
  </svg>
);

// 6. Host Firewall / Wall Icon
export const IconFirewall: React.FC<IconProps> = ({ size = 18, color, className, ...props }) => (
  <svg
    {...defaultProps}
    width={size}
    height={size}
    stroke={color || "currentColor"}
    className={`waf-icon ${className || ""}`}
    {...props}
  >
    <rect x="3" y="3" width="18" height="18" rx="2" />
    <path d="M3 9h18" />
    <path d="M3 15h18" />
    <path d="M9 3v6" />
    <path d="M15 3v6" />
    <path d="M6 9v6" />
    <path d="M12 9v6" />
    <path d="M18 9v6" />
    <path d="M9 15v6" />
    <path d="M15 15v6" />
  </svg>
);

// 7. AppSec Marketplace / Plugin Icon
export const IconPlug: React.FC<IconProps> = ({ size = 18, color, className, ...props }) => (
  <svg
    {...defaultProps}
    width={size}
    height={size}
    stroke={color || "currentColor"}
    className={`waf-icon ${className || ""}`}
    {...props}
  >
    <path d="M12 22v-5" />
    <path d="M9 8V2" />
    <path d="M15 8V2" />
    <path d="M18 8v5a6 6 0 0 1-12 0V8z" />
  </svg>
);

// 8. Lightning / Live Threat Stream Icon
export const IconZap: React.FC<IconProps> = ({ size = 18, color, className, ...props }) => (
  <svg
    {...defaultProps}
    width={size}
    height={size}
    stroke={color || "currentColor"}
    className={`waf-icon ${className || ""}`}
    {...props}
  >
    <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
  </svg>
);

// 9. Flask / Mock Backend Icon
export const IconFlask: React.FC<IconProps> = ({ size = 18, color, className, ...props }) => (
  <svg
    {...defaultProps}
    width={size}
    height={size}
    stroke={color || "currentColor"}
    className={`waf-icon ${className || ""}`}
    {...props}
  >
    <path d="M10 2v7.31L4.14 19.5A2 2 0 0 0 5.86 22h12.28a2 2 0 0 0 1.72-2.5L14 9.31V2" />
    <line x1="8.5" y1="2" x2="15.5" y2="2" />
    <line x1="7" y1="16" x2="17" y2="16" />
  </svg>
);

// 10. Eye / Preview Icon
export const IconEye: React.FC<IconProps> = ({ size = 18, color, className, ...props }) => (
  <svg
    {...defaultProps}
    width={size}
    height={size}
    stroke={color || "currentColor"}
    className={`waf-icon ${className || ""}`}
    {...props}
  >
    <path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z" />
    <circle cx="12" cy="12" r="3" />
  </svg>
);

// 11. Copy / Clipboard Icon
export const IconCopy: React.FC<IconProps> = ({ size = 18, color, className, ...props }) => (
  <svg
    {...defaultProps}
    width={size}
    height={size}
    stroke={color || "currentColor"}
    className={`waf-icon ${className || ""}`}
    {...props}
  >
    <rect width="13" height="13" x="9" y="9" rx="2" ry="2" />
    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
  </svg>
);

// 12. Checkmark Icon
export const IconCheck: React.FC<IconProps> = ({ size = 18, color, className, ...props }) => (
  <svg
    {...defaultProps}
    width={size}
    height={size}
    stroke={color || "currentColor"}
    className={`waf-icon ${className || ""}`}
    {...props}
  >
    <polyline points="20 6 9 17 4 12" />
  </svg>
);

// 13. Close / Dismiss Icon
export const IconClose: React.FC<IconProps> = ({ size = 18, color, className, ...props }) => (
  <svg
    {...defaultProps}
    width={size}
    height={size}
    stroke={color || "currentColor"}
    className={`waf-icon ${className || ""}`}
    {...props}
  >
    <line x1="18" y1="6" x2="6" y2="18" />
    <line x1="6" y1="6" x2="18" y2="18" />
  </svg>
);

// 14. Server / Upstream Host Icon
export const IconServer: React.FC<IconProps> = ({ size = 18, color, className, ...props }) => (
  <svg
    {...defaultProps}
    width={size}
    height={size}
    stroke={color || "currentColor"}
    className={`waf-icon ${className || ""}`}
    {...props}
  >
    <rect width="20" height="8" x="2" y="2" rx="2" ry="2" />
    <rect width="20" height="8" x="2" y="14" rx="2" ry="2" />
    <line x1="6" y1="6" x2="6.01" y2="6" strokeWidth={3} />
    <line x1="6" y1="18" x2="6.01" y2="18" strokeWidth={3} />
  </svg>
);

// 15. Right Arrow Icon
export const IconArrowRight: React.FC<IconProps> = ({ size = 18, color, className, ...props }) => (
  <svg
    {...defaultProps}
    width={size}
    height={size}
    stroke={color || "currentColor"}
    className={`waf-icon ${className || ""}`}
    {...props}
  >
    <path d="M5 12h14" />
    <path d="m12 5 7 7-7 7" />
  </svg>
);
