import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "@/lib/api";
import type { MeResponse, SimResult, SimScenario } from "@/lib/types";
import Simulator from "./Simulator";

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return {
    ...actual,
    api: { ...actual.api, me: vi.fn(), simScenarios: vi.fn(), simRuns: vi.fn(), runSimulation: vi.fn(), runBenchmark: vi.fn(), simRun: vi.fn() },
  };
});
vi.mock("@/components/StatusStrip", () => ({ SimulatedBadge: () => <span>SIMULATED</span> }));

const scenario: SimScenario = {
  id: "error_spike", title: "Application error spike", description: "Eligibility fails.", seed: 1101,
  expected_alerts: "error_rate incident on eligibility.", expected_severity: ["HIGH", "CRITICAL"], expected_kind: "error_rate",
  expected_entity: "eligibility", max_detection_delay_s: 120, min_evidence: 5, must_resolve: false, known_limit: false, inject_seconds: 300, synthetic: true,
};
const limitScenario: SimScenario = { ...scenario, id: "mild_degradation", title: "Mild degradation", known_limit: true };

const result: SimResult = {
  scenario_id: "error_spike", title: "Application error spike", description: "d", seed: 1101, synthetic: true, known_limit: false, passed: true,
  summary: "PASS: Application error spike", expected_alerts: "error_rate incident on eligibility.",
  checks: [
    { name: "detected", passed: true, expected: "error_rate incident for eligibility", observed: "error_rate #1" },
    { name: "false_positives", passed: false, expected: 0, observed: 1 },
  ],
  metrics: { detection_delay_s: 5.2, false_positive_incidents: 1, false_positives_per_hour: 0.4, simulated_hours: 0.6, notification_decisions: 4, staff_notifications: 2, time_to_resolve_s: null, events_processed: {}, alerts: 3, incidents: 2 },
  incidents: [{ incident_id: 1, kind: "error_rate", entity: "eligibility", peak_severity: "CRITICAL", state: "RESOLVED", first_alert_at: "2026-03-10T16:15:05Z", alert_count: 9, evidence_count: 15, evidence_quality: "strong", resolved_at: null, label: "expected" }],
  isolation: { database: "temporary SQLite file, deleted after the run", aws_mode: "off", email: "disabled", external_calls: 0 },
};

const me = (role: MeResponse["role"]): MeResponse => ({
  role, actor: role, authenticated: true, open_access: false,
  can: { operate: role !== "viewer", admin: role === "admin" },
});

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter><Simulator /></MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.mocked(api.me).mockResolvedValue(me("operator"));
  vi.mocked(api.simScenarios).mockResolvedValue({ scenarios: [scenario, limitScenario], synthetic_only: true, note: "" });
  vi.mocked(api.simRuns).mockResolvedValue({ items: [] });
});

describe("Simulator", () => {
  it("lists scenarios with their expected alerts, severity, delay and seed, and flags known limits", async () => {
    renderPage();
    const card = (await screen.findByText("Application error spike")).closest("li") as HTMLElement;
    expect(within(card).getByText("error_rate incident on eligibility.")).toBeInTheDocument();
    expect(within(card).getByText("HIGH or CRITICAL")).toBeInTheDocument();
    expect(within(card).getByText("2 min of injection")).toBeInTheDocument();
    expect(within(card).getByText("1101")).toBeInTheDocument();
    expect(screen.getByText(/Known limit: this scenario is not reliably detected/)).toBeInTheDocument();
    expect(screen.getByText(/never touch real systems/)).toBeInTheDocument();
  });

  it("runs a scenario and shows delay, false positives, every check and the isolation statement", async () => {
    const user = userEvent.setup();
    vi.mocked(api.runSimulation).mockResolvedValue({ ...result, id: 5 });
    renderPage();
    await user.click(await screen.findByRole("button", { name: "Run Application error spike" }));
    expect(api.runSimulation).toHaveBeenCalledWith("error_spike");
    const table = await screen.findByRole("table", { name: "Checks for Application error spike" });
    expect(within(table).getByText("Expected incident detected")).toBeInTheDocument();
    expect(within(table).getAllByText("Fail")).toHaveLength(1);
    expect(screen.getByText("5 s")).toBeInTheDocument();                       // detection delay
    expect(screen.getByText("0.40 per hour")).toBeInTheDocument();             // false-positive rate
    expect(screen.getByText(/external calls 0/)).toBeInTheDocument();
    expect(screen.getAllByText(/Critical|CRITICAL/).length).toBeGreaterThan(0);
    expect(screen.getByText("Passed")).toBeInTheDocument();
  });

  it("disables running for a viewer and says why", async () => {
    vi.mocked(api.me).mockResolvedValue(me("viewer"));
    renderPage();
    expect(await screen.findByText(/needs the operator role/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Run Application error spike" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Run benchmark" })).toBeDisabled();
  });

  it("lets only an admin run the benchmark and reports it honestly", async () => {
    const user = userEvent.setup();
    vi.mocked(api.me).mockResolvedValue(me("admin"));
    vi.mocked(api.runBenchmark).mockResolvedValue({
      seeds: [11, 22, 33], runs: [],
      summary: { runs: 21, passed: 17, injected_runs: 15, detected: 15, detection_rate: 1, detection_delay_s: { median: 10, max: 216 }, known_limit_runs: 3, known_limit_detected: 1, control_runs: 3, control_false_positives: 1, control_false_positives_per_hour: 0.5, all_false_positives: 2, all_false_positives_per_hour: 0.14 },
    });
    renderPage();
    const button = await screen.findByRole("button", { name: "Run benchmark" });
    await vi.waitFor(() => expect(button).toBeEnabled());
    await user.click(button);
    expect(await screen.findByText("Detected 15 of 15 injected runs (100%).")).toBeInTheDocument();
    expect(screen.getByText(/1 false positive in 3 runs/)).toBeInTheDocument();
    expect(screen.getByText(/these figures describe this generator, not real traffic/)).toBeInTheDocument();
  });

  it("shows an empty state for history and an error state when scenarios cannot load", async () => {
    renderPage();
    expect(await screen.findByText("No simulation runs yet")).toBeInTheDocument();
  });

  it("shows the error state with retry when the backend is unreachable", async () => {
    vi.mocked(api.simScenarios).mockRejectedValue(new Error("The HEALTHTRACE backend is unreachable."));
    renderPage();
    expect(await screen.findAllByText("Backend unreachable")).not.toHaveLength(0);
  });

  it("reports a failed run through the toast path without crashing", async () => {
    const user = userEvent.setup();
    vi.mocked(api.runSimulation).mockRejectedValue(new Error("a simulation is already running"));
    renderPage();
    await user.click(await screen.findByRole("button", { name: "Run Application error spike" }));
    await vi.waitFor(() => expect(api.runSimulation).toHaveBeenCalled());
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });

  it("lists previous runs and reopens one", async () => {
    const user = userEvent.setup();
    vi.mocked(api.simRuns).mockResolvedValue({ items: [{ id: 9, created_at: "2026-10-10T08:00:00Z", scenario_id: "error_spike", seed: 1101, passed: true, summary: "PASS: Application error spike", requested_by: "operator" }] });
    vi.mocked(api.simRun).mockResolvedValue({ id: 9, result });
    renderPage();
    await user.click(await screen.findByRole("button", { name: /Application error spike.*seed 1101/ }));
    expect(await screen.findByRole("table", { name: "Checks for Application error spike" })).toBeInTheDocument();
  });
});
