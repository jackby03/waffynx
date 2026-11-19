export type ViewId =
  | "overview"
  | "events"
  | "sites"
  | "zero-trust"
  | "managed-rules"
  | "custom-rules"
  | "firewall"
  | "learning"
  | "pipeline"
  | "marketplace"
  | "audit"
  | "system";

export interface NavEntry {
  id: ViewId;
  path: string;
  label: string;
  section: "COMMAND CENTER" | "APPLICATIONS" | "WAF & PROTECTION" | "EXTENSIONS" | "GOVERNANCE";
  subtitle: string;
}

export const NAV_ITEMS: NavEntry[] = [
  {
    id: "overview",
    path: "/overview",
    label: "Overview",
    section: "COMMAND CENTER",
    subtitle: "Real-time enforcement posture, block timeline, and top sources",
  },
  {
    id: "events",
    path: "/events",
    label: "Security Events",
    section: "COMMAND CENTER",
    subtitle: "Stored event ring plus live SSE forensics and rapid IP mitigation",
  },
  {
    id: "sites",
    path: "/sites",
    label: "Protected Sites",
    section: "APPLICATIONS",
    subtitle: "Reverse-proxy topology pushed dynamically via Envoy xDS or nginx -t",
  },
  {
    id: "zero-trust",
    path: "/zero-trust",
    label: "Zero Trust & Mesh",
    section: "WAF & PROTECTION",
    subtitle: "Continuous ext_authz policies, Envoy xDS cluster topology, and FP exclusions",
  },
  {
    id: "managed-rules",
    path: "/waf/managed",
    label: "Managed Ruleset",
    section: "WAF & PROTECTION",
    subtitle: "Immutable Aho-Corasick signature catalog compiled into this build",
  },
  {
    id: "custom-rules",
    path: "/waf/custom",
    label: "Custom Rules",
    section: "WAF & PROTECTION",
    subtitle: "Dynamic L7 policy rules enforced live by the Go sidecar",
  },
  {
    id: "firewall",
    path: "/waf/firewall",
    label: "IP Access & Bans",
    section: "WAF & PROTECTION",
    subtitle: "WAF-layer IP bans and optional host kernel firewall status",
  },
  {
    id: "learning",
    path: "/waf/learning",
    label: "Learning & AppSec",
    section: "WAF & PROTECTION",
    subtitle: "Behavioral traffic analysis, scorer posture, and rule suggestions",
  },
  {
    id: "pipeline",
    path: "/plugins",
    label: "Inspection Pipeline",
    section: "EXTENSIONS",
    subtitle: "Registered inspection stages and plugin execution priority",
  },
  {
    id: "marketplace",
    path: "/marketplace",
    label: "Marketplace",
    section: "EXTENSIONS",
    subtitle: "Installable AppSec extension packages from the control-plane store",
  },
  {
    id: "audit",
    path: "/audit",
    label: "Audit Log",
    section: "GOVERNANCE",
    subtitle: "Administrative actions and authenticated API access trail",
  },
  {
    id: "system",
    path: "/system",
    label: "System & Config",
    section: "GOVERNANCE",
    subtitle: "Go runtime health, Prometheus metrics, and runtime YAML configuration",
  },
];

export function viewFromPathname(pathname: string): ViewId {
  const clean = pathname.replace(/\/+$/, "") || "/overview";
  const found = NAV_ITEMS.find((n) => n.path === clean);
  return found ? found.id : "overview";
}

export function navEntryFor(id: ViewId): NavEntry {
  return NAV_ITEMS.find((n) => n.id === id) ?? NAV_ITEMS[0];
}
