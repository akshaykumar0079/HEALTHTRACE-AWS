import type { AnomalyKind, IncidentState, Severity } from "./types";

export const SEVERITY_ORDER: Record<Severity, number> = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };
export const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

export const SEVERITY_COLOR: Record<Severity, string> = {
  LOW: "var(--color-sev-low)",
  MEDIUM: "var(--color-sev-medium)",
  HIGH: "var(--color-sev-high)",
  CRITICAL: "var(--color-sev-critical)",
};

export const SEVERITY_HEX: Record<Severity, string> = {
  LOW: "#7fa6d9",
  MEDIUM: "#e3b35a",
  HIGH: "#ee8a52",
  CRITICAL: "#f05a73",
};

export const SIGNAL_HEX = "#56dcc8";

export const KIND_LABEL: Record<AnomalyKind, string> = {
  error_rate: "Error rate spike",
  latency_degradation: "Latency degradation",
  hipaa_bulk_access: "Bulk record access",
  hipaa_bulk_export: "Bulk record export",
  hipaa_off_hours: "Off-hours access",
  hipaa_region_mismatch: "Cross-region access",
};

export const STATE_LABEL: Record<IncidentState, string> = {
  OPEN: "New",
  ACKNOWLEDGED: "Acknowledged",
  INVESTIGATING: "Investigating",
  RESOLVED: "Resolved",
};

export const STATES: IncidentState[] = ["OPEN", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED"];

export const isHipaaKind = (kind: AnomalyKind) => kind.startsWith("hipaa_");

const FALLBACK_LABELS: Record<string, string> = {
  prior_auth: "Prior Authorization",
  eligibility: "Eligibility",
  pharmacy: "Pharmacy",
  claims: "Claims",
  batch: "Batch Jobs",
};

export function serviceLabel(service: string | null | undefined, labels?: Record<string, string>): string {
  if (!service) return "HIPAA audit";
  return labels?.[service] ?? FALLBACK_LABELS[service] ?? service;
}

export function subjectOf(item: { service: string | null; user_id: string | null }): string {
  return item.service ? serviceLabel(item.service) : item.user_id ?? "Unknown";
}

export function pct(value: number | null | undefined, digits = 1): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "-";
  return `${(value * 100).toFixed(digits)}%`;
}

export function ms(value: number | null | undefined): string {
  if (value === null || value === undefined) return "-";
  if (value >= 1000) return `${(value / 1000).toFixed(2)}s`;
  return `${Math.round(value)}ms`;
}

export function num(value: number | null | undefined, digits = 0): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "-";
  return value.toLocaleString("en-US", { maximumFractionDigits: digits, minimumFractionDigits: digits });
}

export function compact(value: number): string {
  return new Intl.NumberFormat("en-US", { notation: "compact", maximumFractionDigits: 1 }).format(value);
}

/** Relative deviation of current vs baseline, e.g. +240%. */
export function deviation(current: number | null | undefined, baseline: number | null | undefined): string {
  if (current == null || baseline == null) return "-";
  if (baseline <= 0) return current > 0 ? "new" : "0%";
  const d = ((current - baseline) / baseline) * 100;
  const sign = d > 0 ? "+" : "";
  return `${sign}${Math.abs(d) >= 1000 ? Math.round(d).toLocaleString("en-US") : d.toFixed(0)}%`;
}

export function duration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return "-";
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h}h ${m % 60}m`;
  return `${Math.floor(h / 24)}d ${h % 24}h`;
}

export function ago(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return "-";
  const diff = (now - new Date(iso).getTime()) / 1000;
  if (diff < 0) return "just now";
  if (diff < 5) return "just now";
  if (diff < 60) return `${Math.floor(diff)}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

const timeFmt = new Intl.DateTimeFormat("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
const dateTimeFmt = new Intl.DateTimeFormat("en-US", {
  month: "short",
  day: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});

export const clock = (iso: string | null | undefined) => (iso ? timeFmt.format(new Date(iso)) : "-");
export const stamp = (iso: string | null | undefined) => (iso ? dateTimeFmt.format(new Date(iso)) : "-");

export function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`;
  return `${(n / 1024 ** 3).toFixed(2)} GB`;
}

export type HealthTone = "healthy" | "learning" | Severity;

export function serviceTone(row: { worst_severity: Severity | null; baseline_ready: boolean }): HealthTone {
  if (row.worst_severity) return row.worst_severity;
  return row.baseline_ready ? "healthy" : "learning";
}

export const TONE_HEX: Record<HealthTone, string> = {
  healthy: SIGNAL_HEX,
  learning: "#627085",
  ...SEVERITY_HEX,
};

export const TONE_LABEL: Record<HealthTone, string> = {
  healthy: "Healthy",
  learning: "Learning baseline",
  LOW: "Low deviation",
  MEDIUM: "Degraded",
  HIGH: "High impact",
  CRITICAL: "Critical",
};
