/**
 * Pure helpers behind the Incident Time Machine. They never mutate their
 * input: replay and selection work on copies, so the stored timeline (and the
 * records behind it) stay exactly as the server returned them.
 */
import type { CoverageStatus, Severity, TimelineCoverage, TimelineEntry, TimelinePhase, TimelineSource } from "./types";

export const PHASES: TimelinePhase[] = ["before", "during", "after"];
export const SOURCES: TimelineSource[] = ["lifecycle", "alerts", "evidence", "metrics"];

export const SOURCE_LABEL: Record<TimelineSource, string> = {
  lifecycle: "Lifecycle",
  alerts: "Alerts",
  evidence: "Evidence",
  metrics: "Window metrics",
};

export const PHASE_LABEL: Record<TimelinePhase, string> = {
  before: "Before the incident",
  during: "During the incident",
  after: "After the incident",
};

const SOURCE_RANK: Record<string, number> = { lifecycle: 0, alerts: 1, evidence: 2, metrics: 3 };

const time = (iso: string) => new Date(iso).getTime();

/** Chronological order; ties keep the server's explainable order (lifecycle, alert, evidence, metric, then id). */
export function sortEntries(entries: readonly TimelineEntry[]): TimelineEntry[] {
  return [...entries].sort(
    (a, b) => time(a.ts) - time(b.ts) || (SOURCE_RANK[a.source] ?? 9) - (SOURCE_RANK[b.source] ?? 9) || a.id.localeCompare(b.id),
  );
}

export function isChronological(entries: readonly TimelineEntry[]): boolean {
  for (let i = 1; i < entries.length; i++) if (time(entries[i - 1].ts) > time(entries[i].ts)) return false;
  return true;
}

/** Which phase a timestamp is in. Both edges of the incident are inclusive, matching the server. */
export function phaseOf(ts: string, openedAt: string, endAt: string): TimelinePhase {
  const t = time(ts);
  if (t < time(openedAt)) return "before";
  if (t > time(endAt)) return "after";
  return "during";
}

/** Entries whose time falls inside [from, to], inclusive at both ends. */
export function withinWindow(entries: readonly TimelineEntry[], from: string, to: string): TimelineEntry[] {
  const lo = time(from);
  const hi = time(to);
  return entries.filter((e) => {
    const t = time(e.ts);
    return t >= lo && t <= hi;
  });
}

export interface EntryFilter {
  sources?: readonly TimelineSource[];
  phases?: readonly TimelinePhase[];
  severities?: readonly Severity[];
  service?: string;
}

/** Severity only narrows entries that carry one: metrics and evidence rows are not dropped by it. */
export function filterEntries(entries: readonly TimelineEntry[], f: EntryFilter): TimelineEntry[] {
  return entries.filter((e) => {
    if (f.sources && !f.sources.includes(e.source)) return false;
    if (f.phases && !f.phases.includes(e.phase)) return false;
    if (f.severities && f.severities.length && e.severity && !f.severities.includes(e.severity)) return false;
    if (f.service && e.service && e.service !== f.service) return false;
    return true;
  });
}

export function countByPhase(entries: readonly TimelineEntry[]): Record<TimelinePhase, number> {
  const out: Record<TimelinePhase, number> = { before: 0, during: 0, after: 0 };
  for (const e of entries) out[e.phase] += 1;
  return out;
}

// -- replay ----------------------------------------------------------------------------------

/** Replay position is an index into the chronological list: -1 means "before anything happened". */
export function clampCursor(cursor: number, length: number): number {
  if (length <= 0) return -1;
  return Math.min(Math.max(Math.trunc(cursor), -1), length - 1);
}

export function stepCursor(cursor: number, length: number, direction: 1 | -1): number {
  return clampCursor(cursor + direction, length);
}

/** The entries that had happened by the replay cursor. Returns a new array; the input is untouched. */
export function entriesUpTo(entries: readonly TimelineEntry[], cursor: number): TimelineEntry[] {
  const c = clampCursor(cursor, entries.length);
  return c < 0 ? [] : entries.slice(0, c + 1);
}

export interface ReplayState {
  status: "NOT_YET_OPENED" | "OPEN" | "ACKNOWLEDGED" | "INVESTIGATING" | "RESOLVED";
  severity: Severity | null;
  occurrences: number;
  at: string | null;
}

const SEV: Record<Severity, number> = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };

/** The incident as it stood after the replayed entries, derived only from stored entries (nothing is invented). */
export function replayState(replayed: readonly TimelineEntry[]): ReplayState {
  let status: ReplayState["status"] = "NOT_YET_OPENED";
  let severity: Severity | null = null;
  let occurrences = 0;
  for (const e of replayed) {
    if (e.source === "alerts" && !e.related) occurrences += 1;
    if (e.source !== "lifecycle") continue;
    if (e.severity && (severity === null || SEV[e.severity] > SEV[severity])) severity = e.severity;
    switch (e.event_type) {
      case "opened":
      case "reopened":
        status = "OPEN";
        break;
      case "acknowledged":
        status = "ACKNOWLEDGED";
        break;
      case "investigating":
        status = "INVESTIGATING";
        break;
      case "resolved":
      case "auto_resolved":
        status = "RESOLVED";
        break;
    }
  }
  return { status, severity, occurrences, at: replayed.length ? replayed[replayed.length - 1].ts : null };
}

// -- selection -------------------------------------------------------------------------------

/** Keep the selection if it is still visible; otherwise there is no selection (never silently pick another event). */
export function reconcileSelection(selectedId: string | null, visible: readonly TimelineEntry[]): string | null {
  return selectedId && visible.some((e) => e.id === selectedId) ? selectedId : null;
}

export function moveSelection(selectedId: string | null, visible: readonly TimelineEntry[], direction: 1 | -1): string | null {
  if (visible.length === 0) return null;
  const index = visible.findIndex((e) => e.id === selectedId);
  if (index < 0) return visible[direction === 1 ? 0 : visible.length - 1].id;
  return visible[Math.min(Math.max(index + direction, 0), visible.length - 1)].id;
}

// -- coverage --------------------------------------------------------------------------------

export interface CoverageNotice {
  tone: "ok" | "warn" | "info";
  title: string;
  body: string;
}

const COVERAGE_TITLE: Record<CoverageStatus, string> = {
  complete: "Window metrics cover the whole window",
  partial: "Window metrics cover only part of this window",
  none: "No window metrics were stored for this window",
  expired: "Window metrics for this window have expired",
  not_applicable: "Window metrics do not apply to this incident",
};

/** Explicit statements about missing history, so the UI never implies data that is not there. */
export function coverageNotices(coverage: TimelineCoverage, entryCount: number): CoverageNotice[] {
  const out: CoverageNotice[] = [];
  const m = coverage.metrics;
  if (m.applicable) {
    out.push({ tone: m.status === "complete" ? "ok" : "warn", title: COVERAGE_TITLE[m.status], body: m.message });
    if (m.gaps.length) {
      out.push({
        tone: "warn",
        title: `${m.gaps.length} gap${m.gaps.length === 1 ? "" : "s"} in window metrics`,
        body: "Nothing was recorded between the gaps, so the chart does not draw a line through them.",
      });
    }
  } else {
    out.push({ tone: "info", title: COVERAGE_TITLE.not_applicable, body: m.message });
  }
  if (coverage.evidence.status === "none") out.push({ tone: "warn", title: "No evidence stored", body: coverage.evidence.message });
  else if (coverage.evidence.status === "capped") out.push({ tone: "warn", title: "Evidence cap reached", body: coverage.evidence.message });
  out.push({ tone: "info", title: "Raw logs are not retained", body: coverage.raw_logs });
  if (entryCount === 0) {
    out.push({ tone: "warn", title: "Nothing stored in this window", body: "No stored events fall inside this window. Nothing has been inferred or generated." });
  }
  return out;
}

export function describeWindow(before: number, after: number): string {
  const f = (m: number) => (m >= 60 && m % 60 === 0 ? `${m / 60} h` : `${m} min`);
  return `${f(before)} before to ${f(after)} after`;
}
