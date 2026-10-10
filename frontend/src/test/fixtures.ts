import type { TimelineEntry, TimelineResponse } from "@/lib/types";

const T0 = Date.parse("2026-03-10T16:00:00Z");
export const iso = (seconds: number) => new Date(T0 + seconds * 1000).toISOString();

export function entry(partial: Partial<TimelineEntry> & Pick<TimelineEntry, "id" | "ts">): TimelineEntry {
  return {
    source: "alerts", event_type: "alert", service: "claims", component: "claims", severity: null,
    summary: partial.id, phase: "during", ...partial,
  };
}

/** A small synthetic incident: two metrics before, open + alert + ack + evidence during, one metric after. */
export function sampleEntries(): TimelineEntry[] {
  return [
    entry({ id: "metric:a", ts: iso(-120), source: "metrics", event_type: "window_metric", summary: "claims: 1/100 errors", phase: "before" }),
    entry({ id: "metric:b", ts: iso(-60), source: "metrics", event_type: "window_metric", summary: "claims: 2/100 errors", phase: "before" }),
    entry({ id: "lifecycle:1", ts: iso(0), source: "lifecycle", event_type: "opened", severity: "HIGH", summary: "Incident opened", phase: "during" }),
    entry({ id: "alert:1", ts: iso(0), source: "alerts", event_type: "alert", severity: "HIGH", summary: "claims error rate 22% vs 2%", phase: "during",
      observed: { error_rate: 0.22 }, baseline: { mean: 0.02 }, z: 9.5, breaches_threshold: true }),
    entry({ id: "evidence:1", ts: iso(5), source: "evidence", event_type: "log", level: "ERROR", summary: "Downstream eligibility check failed", phase: "during" }),
    entry({ id: "lifecycle:2", ts: iso(90), source: "lifecycle", event_type: "acknowledged", severity: "HIGH", summary: "Acknowledged", phase: "during" }),
    entry({ id: "metric:c", ts: iso(300), source: "metrics", event_type: "window_metric", summary: "claims: 0/100 errors", phase: "after" }),
  ];
}

export function timelineResponse(overrides: Partial<TimelineResponse> = {}): TimelineResponse {
  const entries = overrides.entries ?? sampleEntries();
  return {
    incident_id: 1,
    anchor: { opened_at: iso(0), end: iso(120), resolved: true },
    query: { before_minutes: 15, after_minutes: 15, sources: ["metrics", "alerts", "lifecycle", "evidence"], as_of: null },
    entries,
    count: entries.length,
    coverage: {
      window: { from: iso(-900), to: iso(1020) },
      metrics: { applicable: true, status: "complete", points: 3, first: iso(-120), last: iso(300), expected_interval_seconds: 60, gaps: [], message: "Window metrics cover the whole window." },
      evidence: { stored: 1, cap: 200, status: "available", message: "1 masked log record(s) stored." },
      raw_logs: "Raw application and audit logs are not retained after processing.",
      retention: { metrics_hours: 24, metrics_horizon: iso(-86400) },
    },
    downsampling: { applied: false, stride: 1, metric_points_in_window: 3 },
    explanation: {
      rule: { metric: "error_rate" }, rule_text: "Alert when the 60s error rate is at least 3 standard deviations above baseline.",
      kind: "error_rate", alert_id: 1, alert_ts: iso(0), reason: "error rate 22% vs baseline 2%", severity: "HIGH",
      observed: { error_rate: 0.22 }, baseline: { mean: 0.02 }, threshold: { z: 3 }, deviation: { z: 9.5 }, available: true,
    },
    notes: [],
    read_only: true,
    ...overrides,
  };
}
