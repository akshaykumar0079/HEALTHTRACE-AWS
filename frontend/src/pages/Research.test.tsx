import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "@/lib/api";
import type { MeResponse, ResearchExperiment, ResearchInfo, ResearchReport, ResearchUploadResult } from "@/lib/types";
import Research from "./Research";

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      me: vi.fn(), researchInfo: vi.fn(), researchUpload: vi.fn(), researchValidate: vi.fn(), researchRun: vi.fn(),
      researchExperiments: vi.fn(), researchRerun: vi.fn(), researchExperiment: vi.fn(), researchCompare: vi.fn(),
    },
  };
});

const field = (name: string, label: string, required = false, extra = {}) => ({ name, label, required, ...extra });
const info: ResearchInfo = {
  enabled: true,
  warning: "Research prototype. Upload only synthetic or properly de-identified data. This application is not HIPAA-certified.",
  limits: { max_upload_mb: 25, max_rows: 200000, max_columns: 100, max_cell_chars: 2000 },
  formats: [".csv", ".jsonl", ".ndjson"],
  kinds: {
    app: { fields: [field("ts", "Timestamp", true), field("service", "Service", true, { values: ["claims", "pharmacy"] }), field("level", "Event level", false, { values: ["INFO", "WARN", "ERROR"] }), field("status", "Status code")] },
    audit: { fields: [field("ts", "Timestamp", true)] },
    auth: { fields: [field("ts", "Timestamp", true)] },
  },
  services: ["claims", "pharmacy"],
  methods: [
    { id: "current", title: "Current detector", description: "d", kind: "pipeline", service_metric_only: false, sensitivity: false },
    { id: "threshold_10pct", title: "Fixed threshold (10%)", description: "t", kind: "threshold", service_metric_only: true, sensitivity: false },
  ],
  default_methods: ["current"], retention_days: 30, warmup_seconds: 120, external_calls: 0,
};

const uploaded: ResearchUploadResult = {
  upload: { id: "a".repeat(64), filename: "mine.csv", format: "csv", size_bytes: 2048, uploaded_at: "2026-03-10T10:00:00Z" },
  inspection: {
    format: "csv", delimiter: ",", size_bytes: 2048, sha256: "a".repeat(64), rows_parsed: 100, rows_usable: 100, rows_truncated_at_limit: false,
    row_rejects: {}, sensitive_columns: [], masked_columns: ["PatientRef"], distinct_values: { Flag: ["0", "1"], Component: ["claims", "RX"] },
    columns: [
      { name: "Time", kind: "timestamp", non_empty: 100, distinct: 100, sensitive_name: false, masked_in_preview: false },
      { name: "Component", kind: "text", non_empty: 100, distinct: 2, sensitive_name: false, masked_in_preview: false },
      { name: "Severity", kind: "text", non_empty: 100, distinct: 3, sensitive_name: false, masked_in_preview: false },
      { name: "PatientRef", kind: "text", non_empty: 100, distinct: 100, sensitive_name: false, masked_in_preview: true },
      { name: "Flag", kind: "number", non_empty: 100, distinct: 2, sensitive_name: false, masked_in_preview: false },
    ],
    preview_rows: [{ row: 1, Time: "2026-03-10T09:00:00Z", Component: "claims", Severity: "info", PatientRef: "[masked: identifier or free text]", Flag: 0 }],
    preview_note: "The preview shows the first rows only.",
  },
};

const okReport: ResearchReport = {
  ok: true, mode: "unlabeled", errors: [], warnings: ["Latency is not mapped: latency anomalies cannot be detected (latency is treated as 0)."],
  rows: { total: 100, accepted: 98, rejected: 2, rejects_by_code: { bad_value: 2 }, first_rows_by_code: { bad_value: [4, 9] }, explanations: { bad_value: "A value could not be interpreted." } },
  time_span: { first: "2026-03-10T09:00:00Z", last: "2026-03-10T09:30:00Z", hours: 0.5 },
};

const experiment = (labeled: boolean): ResearchExperiment => ({
  id: "exp-20260310T100000Z-abcd1234", created_at: "2026-03-10T10:00:00Z", created_by: "op",
  upload: { sha256: "a".repeat(64), filename: "mine.csv", format: "csv", size_bytes: 2048 },
  config: { upload_sha256: "a".repeat(64), mode: labeled ? "labeled" : "descriptive", methods: ["current"], mapping: { kind: "app", columns: {}, values: {}, defaults: {}, timezone: "UTC", label: null } },
  result: {
    dataset: { kind: "app", rows_total: 100, rows_accepted: 98, rows_rejected: 2, first_event_at: null, last_event_at: null, span_hours: 0.5, detector_warmup_seconds: 120, warnings: [] },
    methods: [{
      method: "current", applicable: true, incidents_found: 1,
      incidents: [{ kind: "error_rate", entity: "claims", first_alert_at: "2026-03-10T09:20:00Z", last_alert_at: null, alerts: 3, peak_severity: "HIGH" }],
      evaluation: labeled
        ? {
            mode: "labeled", metrics_measured: true, assumptions: ["The label column is treated as exhaustive ground truth."], false_alarms: [],
            intervals: [{ entity: "claims", start: "2026-03-10T09:19:00Z", end: "2026-03-10T09:22:00Z", labelled_rows: 30, detected: true, delay_s: 12.5, starts_in_detector_warmup: false }],
            metrics: { tp: 1, fp: 0, fn: 0, duplicates: 0, intervals: 1, span_hours: 0.5, precision: 1, recall: 1, f1: 1, false_alarms_per_hour: 0, delay_s: { n: 1, median: 12.5, mean: 12.5, min: 12.5, max: 12.5 } },
          }
        : { mode: "descriptive", metrics_measured: false, metrics: null, note: "No ground-truth labels were used, so precision, recall and false-alarm rate were NOT measured." },
    }],
  },
  results_sha256: "f".repeat(64), disclaimer: "Research prototype. Not HIPAA-certified.",
});

const me = (role: MeResponse["role"]): MeResponse => ({
  role, actor: role, authenticated: true, open_access: false, can: { operate: role !== "viewer", admin: role === "admin" },
});

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter><Research /></MemoryRouter>
    </QueryClientProvider>,
  );
}

const file = (name = "mine.csv") => new File(["a,b\n1,2\n"], name, { type: "text/csv" });

beforeEach(() => {
  vi.mocked(api.me).mockResolvedValue(me("operator"));
  vi.mocked(api.researchInfo).mockResolvedValue(info);
  vi.mocked(api.researchExperiments).mockResolvedValue({ items: [] });
  vi.mocked(api.researchUpload).mockReset().mockResolvedValue(uploaded);
  vi.mocked(api.researchValidate).mockReset().mockResolvedValue(okReport);
  vi.mocked(api.researchRun).mockReset().mockResolvedValue(experiment(false));
});

async function uploadAndValidate(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByLabelText(/I understand/));
  await user.upload(screen.getByLabelText("Dataset file"), file());
  await screen.findByText("Map your columns");
  await user.click(screen.getByRole("button", { name: "Validate mapping" }));
  await screen.findByText("Valid. You can run it.");
}

describe("Research (your data)", () => {
  it("shows the privacy warning first and blocks selecting a file until it is acknowledged", async () => {
    renderPage();
    expect(await screen.findByText(/not HIPAA-certified/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Select CSV or JSON Lines file/ })).toBeDisabled();
    expect(screen.getByLabelText("Dataset file")).toBeDisabled();
    await userEvent.setup().click(screen.getByLabelText(/I understand/));
    expect(screen.getByRole("button", { name: /Select CSV or JSON Lines file/ })).toBeEnabled();
  });

  it("refuses an unsupported file type in the browser without sending it", async () => {
    const user = userEvent.setup({ applyAccept: false });
    renderPage();
    await user.click(await screen.findByLabelText(/I understand/));
    await user.upload(screen.getByLabelText("Dataset file"), file("notes.xlsx"));
    expect(api.researchUpload).not.toHaveBeenCalled();
  });

  it("previews the file, masks identifier columns, and suggests a mapping from the column names", async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByLabelText(/I understand/));
    await user.upload(screen.getByLabelText("Dataset file"), file());
    const table = await screen.findByRole("table", { name: "First rows of the file" });
    expect(within(table).getByText("[masked: identifier or free text]")).toBeInTheDocument();
    expect(within(table).getByText(/PatientRef/)).toBeInTheDocument();
    expect((screen.getByLabelText("Timestamp *") as HTMLSelectElement).value).toBe("Time");
    expect((screen.getByLabelText("Service *") as HTMLSelectElement).value).toBe("Component");
    expect(api.researchUpload).toHaveBeenCalledTimes(1);
  });

  it("does not allow a run until the mapping validates, and clears validation when the mapping changes", async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByLabelText(/I understand/));
    await user.upload(screen.getByLabelText("Dataset file"), file());
    await screen.findByText("Map your columns");
    expect(screen.getByRole("button", { name: "Run evaluation" })).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Validate mapping" }));
    await screen.findByText("Valid. You can run it.");
    expect(screen.getByRole("button", { name: "Run evaluation" })).toBeEnabled();
    await user.selectOptions(screen.getByLabelText("Event level"), "Severity");
    expect(screen.queryByText("Valid. You can run it.")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Run evaluation" })).toBeDisabled();
  });

  it("shows server validation errors, rejected-row reasons and numbers only", async () => {
    vi.mocked(api.researchValidate).mockResolvedValue({
      ok: false, mode: "unlabeled", warnings: [],
      errors: [{ field: "ts", code: "missing_required", message: "'Timestamp' must be mapped to a column." }],
      rows: { total: 10, accepted: 0, rejected: 10, rejects_by_code: { ts_invalid: 10 }, first_rows_by_code: { ts_invalid: [1, 2, 3] }, explanations: { ts_invalid: "The timestamp is missing or not ISO-8601." } },
      unmapped_values: { service: ["MysteryService"] },
    });
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByLabelText(/I understand/));
    await user.upload(screen.getByLabelText("Dataset file"), file());
    await screen.findByText("Map your columns");
    await user.click(screen.getByRole("button", { name: "Validate mapping" }));
    expect(await screen.findByText("Not valid yet. Fix the problems below.")).toBeInTheDocument();
    expect(screen.getByText("'Timestamp' must be mapped to a column.")).toBeInTheDocument();
    expect(screen.getByText("ts_invalid")).toBeInTheDocument();
    expect(screen.getByText("1, 2, 3")).toBeInTheDocument();
    expect(screen.getByText("MysteryService")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Run evaluation" })).toBeDisabled();
  });

  it("presents an unlabeled run as descriptive and never shows precision or recall", async () => {
    const user = userEvent.setup();
    renderPage();
    await uploadAndValidate(user);
    await user.click(screen.getByRole("button", { name: "Run evaluation" }));
    expect(await screen.findByText(/Descriptive results only/)).toBeInTheDocument();
    expect(screen.getByText(/NOT measured/)).toBeInTheDocument();
    expect(screen.queryByText("Precision")).not.toBeInTheDocument();
    expect(screen.queryByText("Recall")).not.toBeInTheDocument();
    expect(screen.queryByText("False alarms / h")).not.toBeInTheDocument();
    expect(api.researchRun).toHaveBeenCalledWith(expect.objectContaining({ upload_id: "a".repeat(64), methods: ["current"], mode: "auto" }));
    const incidents = screen.getByRole("table", { name: "Incidents found by Current detector" });
    expect(within(incidents).getByText("claims")).toBeInTheDocument();           // the incident the detector found
  });

  it("shows measured metrics only for a labelled run, with the assumptions", async () => {
    vi.mocked(api.researchRun).mockResolvedValue(experiment(true));
    const user = userEvent.setup();
    renderPage();
    await uploadAndValidate(user);
    await user.click(screen.getByLabelText(/My file has a column that says/));
    await user.selectOptions(screen.getByLabelText("Label column"), "Flag");
    await user.click(screen.getByRole("checkbox", { name: "1" }));
    await user.click(screen.getByRole("button", { name: "Validate mapping" }));
    await user.click(await screen.findByRole("button", { name: "Run evaluation" }));
    expect(await screen.findByText("Precision")).toBeInTheDocument();
    expect(screen.getByText("Recall")).toBeInTheDocument();
    expect(screen.getByText("False alarms / h")).toBeInTheDocument();
    expect(screen.getByText("12.5 s")).toBeInTheDocument();
    expect(screen.getByText(/treated as exhaustive ground truth/)).toBeInTheDocument();
    const sent = vi.mocked(api.researchRun).mock.calls[0]![0];
    expect(sent.mapping.label).toEqual({ column: "Flag", positive_values: ["1"], scope: "entity", merge_gap_seconds: 60 });
  });

  it("reports whether a repeated experiment reproduced the original", async () => {
    vi.mocked(api.researchRerun).mockResolvedValue({ ...experiment(false), id: "exp-20260310T110000Z-abcd1234", rerun_of: "exp-20260310T100000Z-abcd1234", reproduced: true });
    const user = userEvent.setup();
    renderPage();
    await uploadAndValidate(user);
    await user.click(screen.getByRole("button", { name: "Run evaluation" }));
    await user.click(await screen.findByRole("button", { name: "Repeat" }));
    expect(await screen.findByText(/Reproduced: identical to exp-20260310T100000Z-abcd1234/)).toBeInTheDocument();
  });

  it("lets a viewer see saved experiments but not upload", async () => {
    vi.mocked(api.me).mockResolvedValue(me("viewer"));
    renderPage();
    expect(await screen.findByText(/needs the operator role/)).toBeInTheDocument();
    expect(screen.getByLabelText("Dataset file")).toBeDisabled();
  });

  it("explains when the feature is disabled on the server", async () => {
    vi.mocked(api.researchInfo).mockResolvedValue({ ...info, enabled: false });
    renderPage();
    expect(await screen.findByText("Dataset evaluation is turned off")).toBeInTheDocument();
  });
});
