import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "@/lib/api";
import type { IncidentInsight, InsightResponse } from "@/lib/types";
import { AiInsight } from "./AiInsight";

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, insight: vi.fn(), generateInsight: vi.fn(), me: vi.fn() } };
});

const insightMock = vi.mocked(api.insight);
const generateMock = vi.mocked(api.generateInsight);
const meMock = vi.mocked(api.me);

function insight(over: Partial<IncidentInsight> = {}): IncidentInsight {
  return {
    incident_id: 1, generated_at: "2026-10-20T09:00:00Z", generated_by: "deterministic", model: null, status: "ok",
    fallback_reason: null, dropped_claims: 0,
    summary: { text: "Error rate spike on claims: 3 alerts.", evidence_refs: ["inc:1", "alert:2"] },
    severity_rationale: { text: "Peak severity HIGH.", evidence_refs: ["rule:error_rate"] },
    hypotheses: [{ text: "A dependency may be failing.", evidence_refs: ["alert:2"], label: "hypothesis", confidence: "low" }],
    next_steps: [{ text: "Review the stored evidence records.", evidence_refs: ["agg:ev"] }],
    overall_confidence: "medium", evidence_quality: "moderate", insufficient_evidence: false,
    evidence: [{ id: "inc:1", type: "incident", label: "Incident 1: Error rate spike" }],
    executed_actions: [], disclaimer: "Generated analysis from stored, pseudonymised evidence.", ...over,
  };
}

const response = (i: IncidentInsight, ai: Partial<InsightResponse["ai"]> = {}, stale = false): InsightResponse => ({
  insight: i, stale_ai_available: stale,
  ai: { enabled: false, provider: "none", model_configured: false, deterministic_fallback: true, unavailable_reason: "ai_disabled", ...ai },
});

function renderPanel() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}><AiInsight incidentId={1} /></QueryClientProvider>);
}

beforeEach(() => {
  insightMock.mockReset(); generateMock.mockReset(); meMock.mockReset();
  meMock.mockResolvedValue({ role: "operator", actor: "op", authenticated: true, open_access: false, can: { operate: true, admin: false } });
});

describe("AiInsight", () => {
  it("shows the built-in analysis with evidence ids, labelled hypotheses and no model button when AI is off", async () => {
    insightMock.mockResolvedValue(response(insight()));
    renderPanel();
    expect(await screen.findByText(/Error rate spike on claims/)).toBeInTheDocument();
    expect(screen.getAllByText("alert:2", { selector: "code" }).length).toBeGreaterThan(0);
    expect(screen.getByText(/Hypothesis, low confidence/)).toBeInTheDocument();
    expect(screen.getByText(/Possible causes \(hypotheses, not findings\)/)).toBeInTheDocument();
    expect(screen.getByText(/not done automatically/)).toBeInTheDocument();
    expect(screen.getByText(/Built-in analysis from stored evidence \(no model\)/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Ask local model/ })).not.toBeInTheDocument();
  });

  it("says so when there is not enough evidence and shows no hypotheses", async () => {
    insightMock.mockResolvedValue(response(insight({ insufficient_evidence: true, hypotheses: [] })));
    renderPanel();
    expect(await screen.findByText(/not enough stored evidence/)).toBeInTheDocument();
    expect(screen.queryByText(/Hypothesis,/)).not.toBeInTheDocument();
  });

  it("offers the local model only to operators when one is configured, and explains a fallback", async () => {
    insightMock.mockResolvedValue(response(insight(), { enabled: true, provider: "ollama", model_configured: true, unavailable_reason: null }));
    generateMock.mockResolvedValue(response(insight({ status: "fallback", fallback_reason: "provider_unavailable" }), { enabled: true, model_configured: true }));
    renderPanel();
    const button = await screen.findByRole("button", { name: /Ask local model/ });
    await userEvent.click(button);
    expect(generateMock).toHaveBeenCalledWith(1);
    expect(await screen.findAllByText(/could not be reached/)).not.toHaveLength(0);
  });

  it("hides the model button from viewers", async () => {
    meMock.mockResolvedValue({ role: "viewer", actor: "v", authenticated: true, open_access: false, can: { operate: false, admin: false } });
    insightMock.mockResolvedValue(response(insight(), { enabled: true, provider: "ollama", model_configured: true }));
    renderPanel();
    await screen.findByText(/Error rate spike on claims/);
    expect(screen.queryByRole("button", { name: /Ask local model/ })).not.toBeInTheDocument();
  });

  it("tells the user a stored model answer is hidden when the evidence changed", async () => {
    insightMock.mockResolvedValue(response(insight(), {}, true));
    renderPanel();
    expect(await screen.findByText(/evidence changed since the last model answer/)).toBeInTheDocument();
  });
});
