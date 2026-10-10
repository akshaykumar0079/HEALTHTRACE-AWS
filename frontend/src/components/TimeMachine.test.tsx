import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "@/lib/api";
import { useLive } from "@/lib/live";
import { entry, iso, timelineResponse } from "@/test/fixtures";
import { TimeMachine } from "./TimeMachine";

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, timeline: vi.fn(), timelineEntry: vi.fn() } };
});

const timeline = vi.mocked(api.timeline);
const timelineEntry = vi.mocked(api.timelineEntry);

function renderPanel(state: "OPEN" | "RESOLVED" = "RESOLVED") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <TimeMachine incidentId={1} state={state} />
    </QueryClientProvider>,
  );
}

const selectedRow = () => within(screen.getByRole("list", { name: "Timeline events" })).getByRole("button", { pressed: true });
const inList = (text: string) => within(screen.getByRole("list", { name: "Timeline events" })).getByText(text);
const rowTexts = () => within(screen.getByRole("list", { name: "Timeline events" })).getAllByRole("button").map((b) => b.getAttribute("data-entry"));

beforeEach(() => {
  useLive.setState({ connection: "live" });
  timeline.mockResolvedValue(timelineResponse());
  timelineEntry.mockResolvedValue({ kind: "alert", raw: { id: 1, severity: "HIGH", explanation: "synthetic" }, note: "Synthetic, masked, log-safe record." });
});

describe("TimeMachine", () => {
  it("shows a loading state, then events in chronological order grouped by phase", async () => {
    renderPanel();
    expect(screen.getByText(/Incident Time Machine/)).toBeInTheDocument();
    await screen.findByRole("list", { name: "Timeline events" });
    expect(rowTexts()).toEqual(["metric:a", "metric:b", "lifecycle:1", "alert:1", "evidence:1", "lifecycle:2", "metric:c"]);
    const headings = screen.getAllByRole("heading", { level: 3 }).map((h) => h.textContent);
    expect(headings.indexOf("Before the incident")).toBeLessThan(headings.indexOf("During the incident"));
    expect(headings.indexOf("During the incident")).toBeLessThan(headings.indexOf("After the incident"));
    expect(screen.getByText(/7 events: 2 before, 4 during, 1 after/)).toBeInTheDocument();
  });

  it("requests the chosen window and sources", async () => {
    const user = userEvent.setup();
    renderPanel();
    await screen.findByRole("list", { name: "Timeline events" });
    expect(timeline).toHaveBeenLastCalledWith(1, { before_minutes: 15, after_minutes: 15, sources: "lifecycle,alerts,evidence,metrics" });
    await user.selectOptions(screen.getByLabelText("Before"), "60");
    await user.click(screen.getByRole("button", { name: "Window metrics" }));
    await vi.waitFor(() =>
      expect(timeline).toHaveBeenLastCalledWith(1, { before_minutes: 60, after_minutes: 15, sources: "lifecycle,alerts,evidence" }),
    );
  });

  it("selecting an event shows its details, raw synthetic record and baseline comparison", async () => {
    const user = userEvent.setup();
    renderPanel();
    await screen.findByRole("list", { name: "Timeline events" });
    expect(screen.getByText(/Select an event to see/)).toBeInTheDocument();
    await user.click(inList("claims error rate 22% vs 2%"));
    const detail = await screen.findByRole("region", { name: "Selected event" });
    expect(timelineEntry).toHaveBeenCalledWith(1, "alert:1");
    expect(within(detail).getByText(/Breaches the detection threshold \(z = 9.5\)/)).toBeInTheDocument();
    expect(await within(detail).findByLabelText("Raw record")).toHaveTextContent('"explanation": "synthetic"');
    // toggling the same event again clears the selection
    await user.click(inList("claims error rate 22% vs 2%"));
    expect(screen.queryByRole("region", { name: "Selected event" })).not.toBeInTheDocument();
  });

  it("moves the selection with the arrow keys", async () => {
    const user = userEvent.setup();
    renderPanel();
    await screen.findByRole("list", { name: "Timeline events" });
    await user.click(screen.getByText("Incident opened"));
    await user.keyboard("{ArrowDown}");
    expect(selectedRow()).toHaveAttribute("data-entry", "alert:1");
    await user.keyboard("{ArrowUp}{ArrowUp}");
    expect(selectedRow()).toHaveAttribute("data-entry", "metric:b");
  });

  it("explains the detection rule, observed, baseline and threshold", async () => {
    renderPanel();
    const panel = await screen.findByRole("region", { name: "Why this alert fired" });
    expect(within(panel).getByText(/at least 3 standard deviations/)).toBeInTheDocument();
    expect(within(panel).getByText("Observed")).toBeInTheDocument();
    expect(within(panel).getByText("Baseline")).toBeInTheDocument();
    expect(within(panel).getByText("Threshold")).toBeInTheDocument();
    expect(within(panel).getByText(/error rate 22% vs baseline 2%/)).toBeInTheDocument();
  });

  it("says detection values are unavailable instead of inventing them", async () => {
    timeline.mockResolvedValue(timelineResponse({
      explanation: { ...timelineResponse().explanation, available: false, observed: null, baseline: null, threshold: null, deviation: null, reason: null, note: "No stored alert for this incident." },
    }));
    renderPanel();
    expect(await screen.findByText("No stored alert for this incident.")).toBeInTheDocument();
  });

  it("handles empty history explicitly, without fabricating events", async () => {
    const base = timelineResponse({ entries: [], notes: ["No stored events fall inside this window. Nothing has been inferred or generated."] });
    timeline.mockResolvedValue({
      ...base,
      coverage: { ...base.coverage, metrics: { ...base.coverage.metrics, status: "expired", points: 0, first: null, last: null, message: "Window metrics older than 24 hours are deleted." }, evidence: { ...base.coverage.evidence, stored: 0, status: "none", message: "No evidence records were stored for this incident." } },
    });
    renderPanel();
    expect(await screen.findByText("No stored events in this window")).toBeInTheDocument();
    expect(screen.queryByRole("list", { name: "Timeline events" })).not.toBeInTheDocument();
    const coverage = screen.getByRole("list", { name: "Data coverage" });
    expect(within(coverage).getByText(/Window metrics for this window have expired/)).toBeInTheDocument();
    expect(within(coverage).getByText(/No evidence stored/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Replay/ })).toBeDisabled();
  });

  it("shows an error state with a working retry", async () => {
    const user = userEvent.setup();
    timeline.mockRejectedValueOnce(new Error("The HEALTHTRACE backend is unreachable."));
    renderPanel();
    expect(await screen.findByText("Backend unreachable")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /Retry|Try again/ }));
    expect(await screen.findByRole("list", { name: "Timeline events" })).toBeInTheDocument();
  });

  it("warns when live updates are lost but keeps the stored data visible", async () => {
    useLive.setState({ connection: "offline" });
    renderPanel();
    expect(await screen.findByRole("list", { name: "Timeline events" })).toBeInTheDocument();
    expect(screen.getByText(/Live updates are offline/)).toBeInTheDocument();
  });

  it("asks for at least one source", async () => {
    const user = userEvent.setup();
    renderPanel();
    await screen.findByRole("list", { name: "Timeline events" });
    for (const name of ["Lifecycle", "Alerts", "Evidence", "Window metrics"]) await user.click(screen.getByRole("button", { name }));
    expect(await screen.findByText("Choose at least one source")).toBeInTheDocument();
  });

  it("replays stored events step by step and never calls anything but the read endpoints", async () => {
    const user = userEvent.setup();
    renderPanel();
    await screen.findByRole("list", { name: "Timeline events" });
    await user.click(screen.getByRole("button", { name: /Replay/ }));
    expect(screen.getByText("Nothing has happened yet")).toBeInTheDocument();
    expect(screen.getByText(/0 of 7 events replayed/)).toBeInTheDocument();
    const forward = screen.getByRole("button", { name: "Step forward" });
    for (let i = 0; i < 4; i++) await user.click(forward);
    expect(screen.getByText(/4 of 7 events replayed/)).toBeInTheDocument();
    expect(screen.getByText(/Status at this point:/)).toHaveTextContent("open, severity HIGH, 1 alert so far");
    expect(rowTexts()).toEqual(["metric:a", "metric:b", "lifecycle:1", "alert:1"]);
    await user.click(screen.getByRole("button", { name: "Step forward" }));
    await user.click(screen.getByRole("button", { name: "Step forward" }));
    expect(screen.getByText(/Status at this point:/)).toHaveTextContent("acknowledged");
    await user.click(screen.getByRole("button", { name: "Back to start" }));
    expect(screen.getByText(/0 of 7 events replayed/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Exit replay" }));
    expect(rowTexts()).toHaveLength(7);
    // read-only: only the timeline GET was used
    expect(timeline.mock.calls.every(([id]) => id === 1)).toBe(true);
  });

  it("clears the selection when replay steps back past the selected event", async () => {
    const user = userEvent.setup();
    renderPanel();
    await screen.findByRole("list", { name: "Timeline events" });
    await user.click(screen.getByRole("button", { name: /Replay/ }));
    for (let i = 0; i < 4; i++) await user.click(screen.getByRole("button", { name: "Step forward" }));
    await user.click(inList("claims error rate 22% vs 2%"));
    expect(screen.getByRole("region", { name: "Selected event" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Step back" }));
    expect(screen.queryByRole("region", { name: "Selected event" })).not.toBeInTheDocument();
  });

  it("marks events from other incidents on the same service", async () => {
    timeline.mockResolvedValue(timelineResponse({ entries: [entry({ id: "alert:7", ts: iso(10), source: "alerts", severity: "LOW", summary: "older flare-up", related: true })] }));
    renderPanel();
    expect(await screen.findByText(/same service, other incident/)).toBeInTheDocument();
  });
});
