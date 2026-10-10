import { describe, expect, it } from "vitest";
import { entry, iso, sampleEntries, timelineResponse } from "@/test/fixtures";
import {
  clampCursor, countByPhase, coverageNotices, describeWindow, entriesUpTo, filterEntries, isChronological,
  moveSelection, phaseOf, reconcileSelection, replayState, sortEntries, stepCursor, withinWindow,
} from "./timeline";

describe("ordering", () => {
  it("sorts chronologically and keeps a stable, explainable order for ties", () => {
    const shuffled = [...sampleEntries()].reverse();
    const sorted = sortEntries(shuffled);
    expect(isChronological(sorted)).toBe(true);
    expect(sorted.map((e) => e.id)).toEqual(["metric:a", "metric:b", "lifecycle:1", "alert:1", "evidence:1", "lifecycle:2", "metric:c"]);
  });

  it("breaks same-time ties by source (lifecycle, alert, evidence, metric) then id", () => {
    const t = iso(10);
    const tied = [
      entry({ id: "metric:z", ts: t, source: "metrics" }),
      entry({ id: "alert:2", ts: t, source: "alerts" }),
      entry({ id: "alert:1", ts: t, source: "alerts" }),
      entry({ id: "lifecycle:9", ts: t, source: "lifecycle" }),
      entry({ id: "evidence:1", ts: t, source: "evidence" }),
    ];
    expect(sortEntries(tied).map((e) => e.id)).toEqual(["lifecycle:9", "alert:1", "alert:2", "evidence:1", "metric:z"]);
  });

  it("does not mutate its input", () => {
    const input = Object.freeze([...sampleEntries()].reverse());
    expect(() => sortEntries(input)).not.toThrow();
    expect(input[0].id).toBe("metric:c");
  });

  it("detects an out-of-order list", () => {
    expect(isChronological([...sampleEntries()].reverse())).toBe(false);
    expect(isChronological([])).toBe(true);
  });
});

describe("time boundaries", () => {
  const opened = iso(0);
  const end = iso(120);

  it("treats both edges of the incident as 'during'", () => {
    expect(phaseOf(iso(-0.001), opened, end)).toBe("before");
    expect(phaseOf(opened, opened, end)).toBe("during");
    expect(phaseOf(end, opened, end)).toBe("during");
    expect(phaseOf(iso(120.001), opened, end)).toBe("after");
  });

  it("includes events exactly on the window edges and excludes the next millisecond", () => {
    const edge = [
      entry({ id: "in-lo", ts: iso(-900) }), entry({ id: "out-lo", ts: iso(-900.001) }),
      entry({ id: "in-hi", ts: iso(1020) }), entry({ id: "out-hi", ts: iso(1020.001) }),
    ];
    expect(withinWindow(edge, iso(-900), iso(1020)).map((e) => e.id)).toEqual(["in-lo", "in-hi"]);
  });

  it("describes windows in minutes or hours", () => {
    expect(describeWindow(15, 60)).toBe("15 min before to 1 h after");
  });

  it("counts entries per phase", () => {
    expect(countByPhase(sampleEntries())).toEqual({ before: 2, during: 4, after: 1 });
  });
});

describe("empty and missing history", () => {
  it("replaying nothing yields no entries and a not-yet-opened incident", () => {
    expect(entriesUpTo([], 3)).toEqual([]);
    expect(replayState([])).toEqual({ status: "NOT_YET_OPENED", severity: null, occurrences: 0, at: null });
    expect(clampCursor(5, 0)).toBe(-1);
  });

  it("states plainly that nothing is stored instead of implying data", () => {
    const empty = timelineResponse({ entries: [] });
    const notices = coverageNotices(empty.coverage, 0).map((n) => n.title);
    expect(notices).toContain("Nothing stored in this window");
    expect(notices).toContain("Raw logs are not retained");
  });

  it("reports expired metrics, gaps and capped evidence explicitly", () => {
    const base = timelineResponse();
    const expired = coverageNotices({ ...base.coverage, metrics: { ...base.coverage.metrics, status: "expired", points: 0, message: "Older than retention." } }, 3);
    expect(expired.find((n) => n.title.includes("expired"))?.tone).toBe("warn");
    const gappy = coverageNotices({
      ...base.coverage,
      metrics: { ...base.coverage.metrics, status: "partial", gaps: [{ from: iso(0), to: iso(300), seconds: 300 }] },
      evidence: { ...base.coverage.evidence, status: "capped", message: "cap reached" },
    }, 3).map((n) => n.title);
    expect(gappy).toContain("1 gap in window metrics");
    expect(gappy).toContain("Evidence cap reached");
  });

  it("says metrics do not apply to user-based incidents", () => {
    const base = timelineResponse();
    const notices = coverageNotices({ ...base.coverage, metrics: { ...base.coverage.metrics, applicable: false, status: "not_applicable", message: "User incidents have no service metrics." } }, 2);
    expect(notices[0].title).toMatch(/do not apply/);
    expect(notices[0].tone).toBe("info");
  });
});

describe("replay", () => {
  const sorted = sortEntries(sampleEntries());

  it("steps within bounds and never past either end", () => {
    expect(stepCursor(-1, 7, -1)).toBe(-1);
    expect(stepCursor(-1, 7, 1)).toBe(0);
    expect(stepCursor(6, 7, 1)).toBe(6);
    expect(clampCursor(2.9, 7)).toBe(2);
  });

  it("returns only what had happened by the cursor, without touching the source", () => {
    const frozen = Object.freeze([...sorted]);
    expect(entriesUpTo(frozen, -1)).toEqual([]);
    expect(entriesUpTo(frozen, 2).map((e) => e.id)).toEqual(["metric:a", "metric:b", "lifecycle:1"]);
    expect(entriesUpTo(frozen, 99)).toHaveLength(7);
    expect(frozen).toHaveLength(7);
  });

  it("derives status, severity and occurrences only from replayed entries", () => {
    expect(replayState(entriesUpTo(sorted, 1))).toMatchObject({ status: "NOT_YET_OPENED", occurrences: 0 });
    expect(replayState(entriesUpTo(sorted, 3))).toMatchObject({ status: "OPEN", severity: "HIGH", occurrences: 1 });
    expect(replayState(entriesUpTo(sorted, 5))).toMatchObject({ status: "ACKNOWLEDGED", occurrences: 1 });
  });

  it("does not count alerts from other incidents as occurrences", () => {
    const withRelated = [...sorted, entry({ id: "alert:99", ts: iso(100), source: "alerts", related: true })];
    expect(replayState(sortEntries(withRelated)).occurrences).toBe(1);
  });

  it("handles resolution and reopening", () => {
    const seq = [
      entry({ id: "l1", ts: iso(0), source: "lifecycle", event_type: "opened", severity: "LOW" }),
      entry({ id: "l2", ts: iso(10), source: "lifecycle", event_type: "resolved" }),
      entry({ id: "l3", ts: iso(20), source: "lifecycle", event_type: "reopened", severity: "HIGH" }),
    ];
    expect(replayState(seq.slice(0, 2)).status).toBe("RESOLVED");
    expect(replayState(seq)).toMatchObject({ status: "OPEN", severity: "HIGH" });
  });
});

describe("selection", () => {
  const sorted = sortEntries(sampleEntries());

  it("keeps a selection that is still visible", () => {
    expect(reconcileSelection("alert:1", sorted)).toBe("alert:1");
  });

  it("clears (never reassigns) a selection that left the view", () => {
    const narrowed = filterEntries(sorted, { sources: ["metrics"] });
    expect(reconcileSelection("alert:1", narrowed)).toBeNull();
    expect(reconcileSelection(null, sorted)).toBeNull();
  });

  it("moves with the arrow keys and stops at the ends", () => {
    expect(moveSelection(null, sorted, 1)).toBe("metric:a");
    expect(moveSelection(null, sorted, -1)).toBe("metric:c");
    expect(moveSelection("metric:a", sorted, -1)).toBe("metric:a");
    expect(moveSelection("metric:c", sorted, 1)).toBe("metric:c");
    expect(moveSelection("lifecycle:1", sorted, 1)).toBe("alert:1");
    expect(moveSelection("x", [], 1)).toBeNull();
  });
});

describe("filtering", () => {
  const sorted = sortEntries(sampleEntries());
  it("filters by source and phase", () => {
    expect(filterEntries(sorted, { sources: ["alerts", "lifecycle"] }).map((e) => e.id)).toEqual(["lifecycle:1", "alert:1", "lifecycle:2"]);
    expect(filterEntries(sorted, { phases: ["after"] }).map((e) => e.id)).toEqual(["metric:c"]);
  });
  it("severity narrows only entries that carry one", () => {
    const ids = filterEntries(sorted, { severities: ["CRITICAL"] }).map((e) => e.id);
    expect(ids).not.toContain("alert:1");
    expect(ids).toContain("metric:a");
  });
});
