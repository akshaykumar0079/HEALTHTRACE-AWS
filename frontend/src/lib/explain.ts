import type { Alert, AppConfigResponse, DetectionRule, Incident } from "./types";
import { ms, num, pct, serviceLabel } from "./format";

export interface Explanation {
  current: { label: string; value: string; detail: string };
  normal: { label: string; value: string; detail: string };
  rule: { label: string; value: string; detail: string };
  checks: { label: string; passed: boolean; detail: string }[];
}

const n = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);

/** Why an alert fired, in the detector's own terms. */
export function explain(alert: Alert, rule: DetectionRule): Explanation {
  const m = alert.metrics;
  if (alert.kind === "error_rate" || alert.kind === "latency_degradation") {
    const latency = alert.kind === "latency_degradation";
    const current = n(latency ? m.p95_latency_ms : m.error_rate) ?? 0;
    const mean = n(m.baseline_mean);
    const std = n(m.baseline_std);
    const minStd = rule.min_std ?? (latency ? 20 : 0.01);
    const stdEff = std != null ? Math.max(std, minStd) : minStd;
    const z = n(m.z) ?? (mean != null ? (current - mean) / stdEff : 0);
    const zt = rule.z_threshold ?? (latency ? 4 : 3);
    const fmt = latency ? ms : (v: number) => pct(v, 1);
    const checks = [
      { label: `z-score at least ${zt}`, passed: z >= zt, detail: `z = ${z.toFixed(1)}` },
    ];
    if (!latency) {
      checks.push(
        { label: `At least ${rule.min_errors ?? 5} errors in the window`, passed: (n(m.errors) ?? 0) >= (rule.min_errors ?? 5), detail: `${num(n(m.errors) ?? 0)} errors` },
        { label: `Error rate at least ${pct(rule.min_rate ?? 0.05, 0)}`, passed: current >= (rule.min_rate ?? 0.05), detail: pct(current, 1) },
      );
    }
    return {
      current: {
        label: latency ? "Current p95 latency" : "Current error rate",
        value: fmt(current),
        detail: latency
          ? `across ${num(n(m.total) ?? 0)} requests in the last ${rule.window_seconds ?? 60}s`
          : `${num(n(m.errors) ?? 0)} errors out of ${num(n(m.total) ?? 0)} events in the last ${rule.window_seconds ?? 60}s`,
      },
      normal: {
        label: "Normal behaviour",
        value: mean != null ? fmt(mean) : "unknown",
        detail: mean != null
          ? `learned baseline for this hour, spread ${fmt(stdEff)}; normal range up to ${fmt(mean + zt * stdEff)}`
          : "baseline was still warming up",
      },
      rule: {
        label: "Detection rule",
        value: `z ≥ ${zt}`,
        detail: latency
          ? `p95 latency ${zt} standard deviations above its baseline`
          : `error rate ${zt} standard deviations above baseline, with enough errors to rule out noise`,
      },
      checks,
    };
  }

  const h = rule.hipaa;
  switch (alert.kind) {
    case "hipaa_bulk_access": {
      const count = n(m.distinct_patients) ?? 0;
      const mult = n(m.multiplier) ?? 0;
      return {
        current: { label: "Distinct patients", value: num(count), detail: `accessed by ${alert.user_id} in the last 10 minutes` },
        normal: {
          label: "Normal behaviour",
          value: mult > 0 && count > 0 ? num(count / mult) : "no history",
          detail: "this user's own learned access baseline per 10 minutes",
        },
        rule: {
          label: "Detection rule",
          value: `> ${h ? num(h.bulk_min_threshold) : "floor"}`,
          detail: `more than ${h?.bulk_multiplier_high ?? 3}x the user's baseline, and above the ${h ? num(h.bulk_min_threshold) : ""} patient floor`,
        },
        checks: [
          { label: "Above bulk threshold", passed: true, detail: `${num(count)} patients, ${mult.toFixed(1)}x baseline` },
          { label: `Critical above ${h?.bulk_multiplier_critical ?? 6}x baseline`, passed: mult > (h?.bulk_multiplier_critical ?? 6), detail: `${mult.toFixed(1)}x` },
        ],
      };
    }
    case "hipaa_bulk_export": {
      const records = n(m.records) ?? 0;
      return {
        current: { label: "Records exported", value: num(records), detail: `by ${alert.user_id} in the last 10 minutes` },
        normal: { label: "Normal behaviour", value: `≤ ${h ? num(h.export_min_threshold) : "floor"}`, detail: "exports are a small share of routine record access" },
        rule: { label: "Detection rule", value: `> ${h ? num(h.export_min_threshold) : "floor"}`, detail: `critical above ${h ? num(h.export_critical_records) : "100"} records` },
        checks: [{ label: "Export volume above floor", passed: true, detail: `${num(records)} records` }],
      };
    }
    case "hipaa_off_hours": {
      const records = n(m.records) ?? 0;
      return {
        current: { label: "Off-hours accesses", value: num(records), detail: `by ${alert.user_id} in the last 10 minutes` },
        normal: {
          label: "Business hours",
          value: h ? `${h.off_hours_start} to ${h.off_hours_end}` : "07:00 to 21:00",
          detail: h ? `judged in ${h.timezone}` : "",
        },
        rule: { label: "Detection rule", value: "outside hours", detail: `high above ${h?.off_hours_high_records ?? 20} records` },
        checks: [{ label: "Access outside business hours", passed: true, detail: `${num(records)} records` }],
      };
    }
    case "hipaa_region_mismatch": {
      const patients = n(m.distinct_patients) ?? 0;
      return {
        current: { label: "Out-of-region patients", value: num(patients), detail: `accessed by ${alert.user_id}` },
        normal: { label: "Normal behaviour", value: "0", detail: "staff access patients in their own region" },
        rule: { label: "Detection rule", value: "region mismatch", detail: `high above ${h?.region_mismatch_medium_max ?? 5} patients` },
        checks: [{ label: "Patient region differs from user region", passed: true, detail: `${num(patients)} patients` }],
      };
    }
    case "auth_suspicious_login": {
      const failures = n(m.failures) ?? 0;
      const threshold = n(m.failure_threshold) ?? rule.failure_threshold ?? 5;
      const flag: unknown = m.unfamiliar_region;
      const unfamiliar = flag === true || flag === "true";
      return {
        current: { label: "Failed logins before success", value: num(failures), detail: `for ${alert.user_id}, then a successful login from ${String(m.success_region ?? "unknown region")}` },
        normal: { label: "Normal behaviour", value: `< ${num(threshold)}`, detail: `staff rarely fail ${num(threshold)} logins in a row; home region is ${String(m.user_region ?? "unknown")}` },
        rule: { label: "Detection rule", value: `≥ ${num(threshold)} failures`, detail: `then a success within ${rule.window_minutes ?? 10} minutes; more serious from an unfamiliar region` },
        checks: [
          { label: `At least ${num(threshold)} failed logins`, passed: failures >= threshold, detail: `${num(failures)} failures` },
          { label: "Success from an unfamiliar region", passed: unfamiliar, detail: unfamiliar ? "yes" : "no" },
        ],
      };
    }
    default:
      return {
        current: { label: "Current", value: "-", detail: "" },
        normal: { label: "Normal", value: "-", detail: "" },
        rule: { label: "Rule", value: "-", detail: "" },
        checks: [],
      };
  }
}

export interface ScoreBreakdown {
  deviation: number;
  criticality: number;
  patientFactor: number;
  score: number;
  thresholds: { low_max: number; medium_max: number; high_max: number };
  weights: { criticality: number; patient: number; zCap: number; patientCap: number };
}

export function scoreBreakdown(alert: Alert, rule: DetectionRule): ScoreBreakdown | null {
  const s = rule.severity;
  const m = alert.metrics;
  const deviation = n(m.deviation_factor);
  const criticality = n(m.criticality);
  const patientFactor = n(m.patient_factor);
  if (!s || deviation == null || criticality == null || patientFactor == null) return null;
  return {
    deviation,
    criticality,
    patientFactor,
    score: alert.score,
    thresholds: s.thresholds,
    weights: { criticality: s.criticality_weight, patient: s.patient_factor_weight, zCap: s.deviation_z_cap, patientCap: s.patient_factor_cap },
  };
}

/** Concrete next steps for the on-call engineer, per anomaly kind. */
export function nextSteps(incident: Incident, config?: AppConfigResponse): string[] {
  const svc = incident.service;
  const deps = svc ? config?.detection.services[svc]?.depends_on ?? [] : [];
  switch (incident.kind) {
    case "error_rate":
      return [
        `Check the related log events below for the dominant error message in ${serviceLabel(svc)}.`,
        deps.length
          ? `Check ${deps.map((d) => serviceLabel(d)).join(" and ")}: ${serviceLabel(svc)} depends on it, and dependency failures surface here first.`
          : `Check recent deploys or configuration changes to ${serviceLabel(svc)}.`,
        "Acknowledge to take ownership. The anomaly resolves itself after 6 consecutive normal windows.",
      ];
    case "latency_degradation":
      return [
        `Compare p95 latency against its baseline in the service view for ${serviceLabel(svc)}.`,
        "Look for saturation: connection pools, downstream timeouts, batch jobs sharing the same resources.",
        "Latency anomalies often precede error spikes. Watch the error-rate band for the next few windows.",
      ];
    case "hipaa_bulk_access":
    case "hipaa_bulk_export":
      return [
        `Confirm with ${incident.user_id}'s manager whether this volume of record access was part of an approved task.`,
        "If not approved, suspend the account and preserve the audit trail for the privacy officer.",
        "Record the outcome before resolving, so the review is traceable.",
      ];
    case "hipaa_off_hours":
      return [
        `Verify whether ${incident.user_id} was scheduled to work at this time.`,
        "Unscheduled off-hours access to patient records should be escalated to the privacy officer.",
      ];
    case "hipaa_region_mismatch":
      return [
        `Check whether ${incident.user_id} was covering another region's caseload.`,
        "Repeated cross-region access without an assignment is a potential privacy violation.",
      ];
    case "auth_suspicious_login":
      return [
        `Contact ${incident.user_id} through a known channel to confirm they made the successful login.`,
        "If they did not, reset the credential, revoke active sessions and review what the account accessed afterwards (see cross-system links below).",
        "Record the outcome before resolving, so the review is traceable.",
      ];
  }
}
