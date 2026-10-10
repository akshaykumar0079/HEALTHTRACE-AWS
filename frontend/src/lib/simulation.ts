import type { BenchmarkSummary, SimCheck, SimResult } from "./types";

export const CHECK_LABEL: Record<string, string> = {
  detected: "Expected incident detected",
  severity: "Severity",
  detection_delay: "Detection delay",
  evidence_count: "Evidence captured",
  evidence_source: "Evidence from the right log",
  resolved: "Resolved automatically",
  false_positives: "No false positives",
  notification_flood: "No notification flood",
};

export const checkLabel = (name: string) => CHECK_LABEL[name] ?? name.replace(/_/g, " ");

export function failedChecks(checks: readonly SimCheck[]): SimCheck[] {
  return checks.filter((c) => !c.passed);
}

/** "12 s", "3 min 20 s", or an explicit "not detected" - a missing value is never shown as zero. */
export function formatDelay(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return "not detected";
  if (seconds < 60) return `${Math.round(seconds)} s`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds - m * 60);
  return s ? `${m} min ${s} s` : `${m} min`;
}

export function formatRate(perHour: number | null | undefined): string {
  if (perHour === null || perHour === undefined) return "n/a";
  return `${perHour.toFixed(2)} per hour`;
}

export function verdict(result: Pick<SimResult, "passed" | "known_limit">): { label: string; tone: "pass" | "fail" | "limit" } {
  if (result.passed) return { label: "Passed", tone: "pass" };
  return result.known_limit ? { label: "Known limit: not reliably detected", tone: "limit" } : { label: "Failed", tone: "fail" };
}

export function benchmarkLines(s: BenchmarkSummary): string[] {
  const pct = (v: number | null) => (v === null ? "n/a" : `${Math.round(v * 100)}%`);
  return [
    `Detected ${s.detected} of ${s.injected_runs} injected runs (${pct(s.detection_rate)}).`,
    `Detection delay: median ${formatDelay(s.detection_delay_s.median)}, worst ${formatDelay(s.detection_delay_s.max)}.`,
    `Normal-traffic control: ${s.control_false_positives} false positive${s.control_false_positives === 1 ? "" : "s"} in ${s.control_runs} run${s.control_runs === 1 ? "" : "s"} (${formatRate(s.control_false_positives_per_hour)}).`,
    `Known-limit scenarios detected: ${s.known_limit_detected} of ${s.known_limit_runs}.`,
  ];
}
