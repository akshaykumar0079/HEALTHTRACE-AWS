import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "@/lib/api";
import type { IncidentTrends as Trends } from "@/lib/types";
import { IncidentTrends } from "./IncidentTrends";

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, incidentTrends: vi.fn() } };
});
const trendsMock = vi.mocked(api.incidentTrends);

const base: Trends = {
  range: { since: "2026-09-27T00:00:00Z", until: "2026-10-27T00:00:00Z", bucket: "day" },
  total: 6,
  series: [{ bucket: "2026-10-20", total: 6, CRITICAL: 1, HIGH: 3, MEDIUM: 2, LOW: 0 }],
  by_severity: [{ key: "CRITICAL", count: 1 }, { key: "HIGH", count: 3 }, { key: "MEDIUM", count: 2 }, { key: "LOW", count: 0 }],
  by_service: [{ key: "claims", label: "claims", count: 4 }, { key: null, label: "No service", count: 2 }],
  by_kind: [{ key: "error_rate", label: "Error rate spike", count: 4 }],
  status: { open: 2, resolved: 4, by_state: { OPEN: 2, RESOLVED: 4 } },
  recurring: [{ kind: "error_rate", label: "Error rate spike", service: "claims", count: 4, first_opened_at: "a", last_opened_at: "b", reopen_count: 1 }],
  resolution: { available: true, sample_size: 4, median_seconds: 900, p90_seconds: 1800, max_seconds: 1800, reason: null },
  resolved_without_valid_duration: 0,
  filters: { service: null, kind: null, severity: null },
  basis: "Counts of stored incidents.",
};

function renderIt() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}><IncidentTrends /></QueryClientProvider>);
}
class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
vi.stubGlobal("ResizeObserver", ResizeObserverStub);

beforeEach(() => vi.resetAllMocks());

describe("IncidentTrends", () => {
  it("shows counts, open vs resolved, recurring patterns and resolution time", async () => {
    trendsMock.mockResolvedValue(base);
    renderIt();
    expect(await screen.findByText("Incidents opened")).toBeInTheDocument();
    expect(screen.getByRole("list", { name: "Recurring incident patterns" })).toHaveTextContent("4x");
    expect(screen.getByText(/p90 30m 0s · 4 resolved incidents/)).toBeInTheDocument();
    expect(screen.getByRole("list", { name: "Incidents by service" })).toBeInTheDocument();
    expect(trendsMock).toHaveBeenCalledWith({ days: 30 });
  });

  it("does not show a resolution figure without enough valid data", async () => {
    trendsMock.mockResolvedValue({
      ...base,
      resolution: { available: false, sample_size: 2, median_seconds: null, p90_seconds: null, max_seconds: null, reason: "Only 2 resolved incident(s) with valid timestamps; at least 5 are needed." },
      resolved_without_valid_duration: 1,
    });
    renderIt();
    expect(await screen.findByText("n/a")).toBeInTheDocument();
    expect(screen.getByText(/at least 5 are needed/)).toBeInTheDocument();
    expect(screen.getByText(/1 resolved incident\(s\) have no valid resolution time/)).toBeInTheDocument();
  });

  it("handles an empty range, an error with retry, and range changes", async () => {
    trendsMock.mockResolvedValueOnce({ ...base, total: 0 });
    renderIt();
    expect(await screen.findByText("No incidents in this range")).toBeInTheDocument();
    trendsMock.mockRejectedValueOnce(new Error("down")).mockResolvedValue(base);
    await userEvent.click(screen.getByRole("radio", { name: "90d" }));
    const retry = await screen.findByRole("button", { name: /retry|try again/i });
    expect(trendsMock).toHaveBeenLastCalledWith({ days: 90 });
    await userEvent.click(retry);
    expect(await screen.findByText("Incidents opened")).toBeInTheDocument();
  });
});
