import {
  BellRinging,
  ChartLineUp,
  Clock,
  Cloud,
  GearSix,
  Graph,
  Heartbeat,
  Lightning,
  Pulse,
  PushPin,
  SquaresFour,
  Terminal,
  Warning,
  type Icon,
} from "@phosphor-icons/react";

export interface NavItem {
  to: string;
  label: string;
  icon: Icon;
  group: "main" | "tools";
  keywords?: string;
}

/** The six primary destinations come first; deeper diagnostics are grouped below them. */
export const NAV: NavItem[] = [
  { to: "/app", label: "Overview", icon: SquaresFour, group: "main", keywords: "home dashboard health summary" },
  { to: "/app/incidents", label: "Incidents", icon: Warning, group: "main", keywords: "anomalies hipaa investigate triage" },
  { to: "/app/events", label: "Live Events", icon: Lightning, group: "main", keywords: "stream feed logs real-time" },
  { to: "/app/pinned", label: "Pinned", icon: PushPin, group: "main", keywords: "bookmarks watchlist" },
  { to: "/app/history", label: "History", icon: Clock, group: "main", keywords: "resolved closed past" },
  { to: "/app/settings", label: "Settings", icon: GearSix, group: "main", keywords: "notifications email detection config token" },
  { to: "/app/monitor", label: "Monitoring", icon: Pulse, group: "tools", keywords: "live monitor error rate chart" },
  { to: "/app/alerts", label: "Alerts", icon: BellRinging, group: "tools", keywords: "alert feed rules" },
  { to: "/app/logs", label: "Log explorer", icon: Terminal, group: "tools", keywords: "search events" },
  { to: "/app/analytics", label: "Analytics", icon: ChartLineUp, group: "tools", keywords: "trends mttr" },
  { to: "/app/services", label: "Services", icon: Graph, group: "tools", keywords: "topology map dependencies" },
  { to: "/app/pulse", label: "System pulse", icon: Heartbeat, group: "tools", keywords: "3d telemetry visual" },
  { to: "/app/aws", label: "AWS integration", icon: Cloud, group: "tools", keywords: "cloudwatch sns aws status" },
];
