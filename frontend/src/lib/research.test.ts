import { describe, expect, it } from "vitest";
import { buildMapping, emptyDraft, formatBytes, num, pct, precheckFile, suggestMapping } from "./research";
import type { ResearchField } from "./types";

const fields: ResearchField[] = ["ts", "service", "level", "status", "latency_ms", "priority", "patient_id", "request_id"].map((name) => ({
  name,
  label: name,
  required: name === "ts",
}));

describe("suggestMapping", () => {
  it("matches common column names, once each", () => {
    const m = suggestMapping(["Time", "Component", "Severity", "HTTP", "Duration_ms", "Urgency", "PatientRef", "ReqID", "Flag"], fields);
    expect(m).toEqual({
      ts: "Time", service: "Component", level: "Severity", status: "HTTP", latency_ms: "Duration_ms",
      priority: "Urgency", patient_id: "PatientRef", request_id: "ReqID",
    });
  });

  it("leaves a field unmapped when nothing fits and never reuses a column", () => {
    const m = suggestMapping(["foo", "bar"], fields);
    expect(m).toEqual({});
    // both columns look like a status; the field takes the first one and the other is not claimed twice
    expect(suggestMapping(["status", "status_code"], fields)).toEqual({ status: "status" });
  });
});

describe("buildMapping", () => {
  it("drops empty choices, auto value maps and defaults shadowed by a column", () => {
    const d = emptyDraft("app", ["time", "svc"], fields);
    d.columns = { ts: "time", service: "svc", level: "" };
    d.defaults = { service: "claims", priority: "routine", latency_ms: "" };
    d.values = { service: { RX: "pharmacy", other: "auto" }, level: { WARNING: "WARN" } };
    const m = buildMapping(d);
    expect(m.columns).toEqual({ ts: "time", service: "svc" });
    expect(m.defaults).toEqual({ priority: "routine" });
    expect(m.values).toEqual({ service: { RX: "pharmacy" } });
    expect(m.label).toBeNull();
    expect(m.timezone).toBe("UTC");
  });

  it("only sends a label when it is enabled and complete", () => {
    const d = emptyDraft("app", [], fields);
    d.label = { enabled: true, column: "Flag", positives: [], scope: "entity", gap: 60 };
    expect(buildMapping(d).label).toBeNull();
    d.label.positives = ["1"];
    expect(buildMapping(d).label).toEqual({ column: "Flag", positive_values: ["1"], scope: "entity", merge_gap_seconds: 60 });
    d.label.enabled = false;
    expect(buildMapping(d).label).toBeNull();
  });
});

describe("precheckFile", () => {
  it("rejects unsupported types, empty files and oversized files", () => {
    const formats = [".csv", ".jsonl", ".ndjson"];
    expect(precheckFile({ name: "a.xlsx", size: 10 }, formats, 25)).toMatch(/Unsupported file type \.xlsx/);
    expect(precheckFile({ name: "noext", size: 10 }, formats, 25)).toMatch(/\(none\)/);
    expect(precheckFile({ name: "a.csv", size: 0 }, formats, 25)).toBe("The file is empty.");
    expect(precheckFile({ name: "a.CSV", size: 26 * 1024 * 1024 }, formats, 25)).toMatch(/25 MB/);
    expect(precheckFile({ name: "a.CSV", size: 1000 }, formats, 25)).toBeNull();
  });
});

describe("formatting", () => {
  it("never prints a number for a missing value", () => {
    expect(pct(null)).toBe("n/a");
    expect(num(undefined)).toBe("n/a");
    expect(pct(0.5)).toBe("50%");
    expect(num(1.2345)).toBe("1.23");
    expect(formatBytes(1536)).toBe("1.5 KB");
  });
});
