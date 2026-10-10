import { describe, expect, it } from "vitest";
import { benchmarkLines, checkLabel, failedChecks, formatDelay, formatRate, verdict } from "./simulation";

describe("simulation formatting", () => {
  it("never shows a missing delay as zero", () => {
    expect(formatDelay(null)).toBe("not detected");
    expect(formatDelay(undefined)).toBe("not detected");
    expect(formatDelay(0)).toBe("0 s");
    expect(formatDelay(42.4)).toBe("42 s");
    expect(formatDelay(200)).toBe("3 min 20 s");
    expect(formatDelay(120)).toBe("2 min");
  });
  it("formats rates and verdicts", () => {
    expect(formatRate(null)).toBe("n/a");
    expect(formatRate(0.5)).toBe("0.50 per hour");
    expect(verdict({ passed: true, known_limit: false }).tone).toBe("pass");
    expect(verdict({ passed: false, known_limit: false }).tone).toBe("fail");
    expect(verdict({ passed: false, known_limit: true }).tone).toBe("limit");
  });
  it("labels checks and lists failures", () => {
    expect(checkLabel("false_positives")).toBe("No false positives");
    expect(checkLabel("something_new")).toBe("something new");
    expect(failedChecks([{ name: "a", passed: true, expected: 1, observed: 1 }, { name: "b", passed: false, expected: 1, observed: 2 }]).map((c) => c.name)).toEqual(["b"]);
  });
  it("summarises a benchmark honestly", () => {
    const lines = benchmarkLines({
      runs: 21, passed: 17, injected_runs: 15, detected: 15, detection_rate: 1, detection_delay_s: { median: 10.1, max: 216.4 },
      known_limit_runs: 3, known_limit_detected: 1, control_runs: 3, control_false_positives: 1, control_false_positives_per_hour: 0.5,
      all_false_positives: 2, all_false_positives_per_hour: 0.14,
    });
    expect(lines[0]).toBe("Detected 15 of 15 injected runs (100%).");
    expect(lines[2]).toContain("1 false positive in 3 runs");
    expect(lines[3]).toContain("1 of 3");
  });
});
