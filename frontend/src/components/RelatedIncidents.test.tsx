import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "@/lib/api";
import type { DuplicatesResponse, IncidentRef, RelatedResponse } from "@/lib/types";
import { DuplicateSuggestions, RelatedIncidents } from "./RelatedIncidents";

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, related: vi.fn(), duplicates: vi.fn() } };
});
const relatedMock = vi.mocked(api.related);
const duplicatesMock = vi.mocked(api.duplicates);

const ref = (id: number, over: Partial<IncidentRef> = {}): IncidentRef => ({
  id, title: "Error rate spike: claims", kind: "error_rate", service: "claims", state: "OPEN", status_label: "New",
  severity: "HIGH", alert_count: 2, opened_at: "2026-10-20T09:04:00Z", last_seen_at: "2026-10-20T09:14:00Z",
  resolved_at: null, ...over,
});
const related = (items: RelatedResponse["related"] = [], considered = 4): RelatedResponse => ({
  source_incident_id: 1, related: items, count: items.length, candidates_considered: considered,
  candidates_truncated: false, criteria: { min_score: 0.4, window_hours: 6, actor_matching: false }, disclaimer: "A match is a lead, not proof.",
});
const dupes = (items: DuplicatesResponse["duplicates"] = [], skipped: string | null = null): DuplicatesResponse => ({
  source_incident_id: 1, duplicates: items, count: items.length, skipped_reason: skipped,
  criteria: { max_gap_minutes: 30, actor_matching: false }, disclaimer: "Needs review.",
});

function wrap(node: React.ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<MemoryRouter><QueryClientProvider client={client}>{node}</QueryClientProvider></MemoryRouter>);
}

beforeEach(() => vi.resetAllMocks());

describe("RelatedIncidents", () => {
  it("shows score, reasons and a link for each related incident", async () => {
    relatedMock.mockResolvedValue(related([{
      source_incident_id: 1, related_incident_id: 2, score: 0.9, reasons: ["Same service (claims).", "Their activity windows overlap in time."],
      signals: ["same_service"], time_gap_seconds: 0, incident: ref(2), basis: "deterministic_match",
    }]));
    wrap(<RelatedIncidents incidentId={1} />);
    expect(await screen.findByText("Same service (claims).")).toBeInTheDocument();
    expect(screen.getByText("Match 0.90")).toBeInTheDocument();
    expect(screen.getByText(/not proof of a shared cause/i)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Open incident 2/ })).toHaveAttribute("href", "/app/incidents/2");
  });

  it("explains an empty result", async () => {
    relatedMock.mockResolvedValue(related([], 3));
    wrap(<RelatedIncidents incidentId={1} />);
    expect(await screen.findByText("No related incidents found")).toBeInTheDocument();
    expect(screen.getByText(/among 3 nearby incidents/)).toBeInTheDocument();
  });

  it("says when the comparison was capped", async () => {
    relatedMock.mockResolvedValue({ ...related([], 300), candidates_truncated: true });
    wrap(<RelatedIncidents incidentId={1} />);
    expect(await screen.findByText(/only the 300 most recent were compared/)).toBeInTheDocument();
  });

  it("shows an error and retries", async () => {
    relatedMock.mockRejectedValueOnce(new Error("boom")).mockResolvedValueOnce(related([], 0));
    wrap(<RelatedIncidents incidentId={1} />);
    const retry = await screen.findByRole("button", { name: /retry|try again/i });
    await userEvent.click(retry);
    expect(await screen.findByText("No related incidents found")).toBeInTheDocument();
    expect(relatedMock).toHaveBeenCalledTimes(2);
  });
});

describe("DuplicateSuggestions", () => {
  it("labels a suggestion as needing review and shows cautions", async () => {
    duplicatesMock.mockResolvedValue(dupes([{
      source_incident_id: 1, candidate_incident_id: 5, confidence: "possible", score: 0.75,
      reasons: ["Same anomaly type (Error rate spike) on the same service (claims)."],
      cautions: ["Both are already resolved; this may be a recurrence rather than a duplicate."],
      time_gap_seconds: 300, incident: ref(5), requires_human_review: true, basis: "deterministic_match",
    }]));
    wrap(<DuplicateSuggestions incidentId={1} />);
    expect(await screen.findByText(/possible duplicate · review needed/)).toBeInTheDocument();
    expect(screen.getByText(/may be a recurrence/)).toBeInTheDocument();
    expect(screen.getByText("Similarity 0.75")).toBeInTheDocument();
    expect(screen.getByText(/nothing is merged, resolved or deleted automatically/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /merge|delete|resolve/i })).toBeNull();
  });

  it("shows why none were made when the check was skipped", async () => {
    duplicatesMock.mockResolvedValue(dupes([], "This anomaly type is grouped per person."));
    wrap(<DuplicateSuggestions incidentId={1} />);
    expect(await screen.findByText("This anomaly type is grouped per person.")).toBeInTheDocument();
  });
});
