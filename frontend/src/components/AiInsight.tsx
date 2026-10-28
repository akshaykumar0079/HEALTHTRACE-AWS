import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Sparkle } from "@phosphor-icons/react";
import { toast } from "@/app/toast";
import { api } from "@/lib/api";
import type { IncidentInsight, InsightClaim } from "@/lib/types";
import { Button, ErrorState, Panel, PanelHeader, Skeleton, cx } from "./ui";

const FALLBACK_TEXT: Record<string, string> = {
  ai_disabled: "The local model is switched off, so this is the built-in analysis.",
  provider_not_configured: "No local model is configured, so this is the built-in analysis.",
  provider_unavailable: "The local model could not be reached, so this is the built-in analysis.",
  provider_error: "The local model returned an error, so this is the built-in analysis.",
  invalid_response: "The local model's answer failed the evidence checks and was discarded. This is the built-in analysis.",
  prompt_too_large: "The evidence was too large for the model prompt. This is the built-in analysis.",
  sanitization_failed: "The prompt did not pass the privacy check and was not sent. This is the built-in analysis.",
};

function Refs({ refs, labels }: { refs: string[]; labels: Map<string, string> }) {
  if (!refs.length) return null;
  return (
    <span className="ml-1.5 inline-flex flex-wrap gap-1 align-middle" aria-label="Evidence">
      {refs.map((r) => (
        <code
          key={r}
          title={labels.get(r) ?? r}
          className="rounded bg-ink-800 px-1.5 py-0.5 font-mono text-[10.5px] text-fg-dim shadow-[inset_0_0_0_1px_var(--hairline)]"
        >
          {r}
        </code>
      ))}
    </span>
  );
}

function ClaimItem({ claim, labels }: { claim: InsightClaim; labels: Map<string, string> }) {
  return (
    <>
      {claim.text}
      <Refs refs={claim.evidence_refs} labels={labels} />
    </>
  );
}

export function InsightBody({ insight }: { insight: IncidentInsight }) {
  const labels = new Map(insight.evidence.map((e) => [e.id, e.label] as const));
  return (
    <div className="space-y-5 border-t border-[var(--hairline)] px-5 py-5">
      <div>
        <p className="text-[12px] text-fg-dim">Summary</p>
        <p className="mt-1.5 max-w-[80ch] text-[13.5px] leading-relaxed text-fg">
          <ClaimItem claim={insight.summary} labels={labels} />
        </p>
      </div>
      <div>
        <p className="text-[12px] text-fg-dim">Why this severity</p>
        <p className="mt-1.5 max-w-[80ch] text-[13px] leading-relaxed text-fg-muted">
          <ClaimItem claim={insight.severity_rationale} labels={labels} />
        </p>
      </div>
      {insight.insufficient_evidence && (
        <p role="status" className="rounded-[12px] bg-ink-800 px-4 py-2.5 text-[12.5px] text-fg-muted shadow-[inset_0_0_0_1px_var(--hairline)]">
          There is not enough stored evidence to suggest causes for this incident.
        </p>
      )}
      {insight.hypotheses.length > 0 && (
        <div>
          <p className="text-[12px] text-fg-dim">Possible causes (hypotheses, not findings)</p>
          <ul className="mt-2 space-y-2">
            {insight.hypotheses.map((h, i) => (
              <li key={i} className="flex gap-3 text-[13px] leading-relaxed text-fg-muted">
                <span
                  className={cx(
                    "mt-0.5 h-fit shrink-0 rounded-full px-2 py-0.5 text-[10.5px] font-medium uppercase tracking-wide",
                    h.confidence === "medium" ? "bg-[#e0b34a1f] text-[#e0b34a]" : "bg-ink-800 text-fg-dim",
                  )}
                >
                  Hypothesis, {h.confidence} confidence
                </span>
                <span><ClaimItem claim={h} labels={labels} /></span>
              </li>
            ))}
          </ul>
        </div>
      )}
      <div>
        <p className="text-[12px] text-fg-dim">Suggested next steps (not done automatically)</p>
        <ol className="mt-2 list-decimal space-y-1.5 pl-5 text-[13px] leading-relaxed text-fg-muted">
          {insight.next_steps.map((s, i) => (
            <li key={i}><ClaimItem claim={s} labels={labels} /></li>
          ))}
        </ol>
      </div>
      <p className="text-[11.5px] leading-relaxed text-fg-dim">
        Overall confidence: {insight.overall_confidence}. Evidence stored: {insight.evidence_quality}. {insight.disclaimer}
      </p>
    </div>
  );
}

export function AiInsight({ incidentId }: { incidentId: number }) {
  const client = useQueryClient();
  const key = ["insight", incidentId];
  const { data, isLoading, error, refetch } = useQuery({ queryKey: key, queryFn: () => api.insight(incidentId) });
  const me = useQuery({ queryKey: ["me"], queryFn: api.me, staleTime: 60_000 });
  const generate = useMutation({
    mutationFn: () => api.generateInsight(incidentId),
    onSuccess: (r) => {
      client.setQueryData(key, r);
      if (r.insight.status === "fallback") toast.error("Local model not used", FALLBACK_TEXT[r.insight.fallback_reason ?? ""] ?? "Showing the built-in analysis.");
    },
    onError: (e: unknown) => toast.error("Could not generate", e instanceof Error ? e.message : undefined),
  });

  if (isLoading) return <Skeleton className="h-40" />;
  if (error || !data) return <ErrorState error={error ?? new Error("Insight unavailable.")} onRetry={() => refetch()} />;

  const { insight, ai, stale_ai_available } = data;
  const source =
    insight.generated_by === "ollama"
      ? `Local model ${insight.model ?? ""}, checked against stored evidence`
      : "Built-in analysis from stored evidence (no model)";
  return (
    <Panel>
      <PanelHeader
        title={
          <span className="inline-flex items-center gap-2">
            <Sparkle size={15} weight="fill" className="text-signal" /> AI incident insight
          </span>
        }
        description={`${source}. Recommendations only: nothing here has been acted on.`}
        actions={
          ai.model_configured && me.data?.can.operate ? (
            <Button size="sm" busy={generate.isPending} onClick={() => generate.mutate()}>
              Ask local model
            </Button>
          ) : undefined
        }
      />
      {stale_ai_available && insight.generated_by === "deterministic" && (
        <p role="status" className="mx-5 mb-3 rounded-[12px] bg-ink-800 px-4 py-2.5 text-[12.5px] text-fg-muted shadow-[inset_0_0_0_1px_var(--hairline)]">
          The evidence changed since the last model answer, so it is hidden. Ask the local model again for an updated one.
        </p>
      )}
      {insight.status === "fallback" && (
        <p role="status" className="mx-5 mb-3 rounded-[12px] bg-ink-800 px-4 py-2.5 text-[12.5px] text-fg-muted shadow-[inset_0_0_0_1px_var(--hairline)]">
          {FALLBACK_TEXT[insight.fallback_reason ?? ""] ?? "Showing the built-in analysis."}
        </p>
      )}
      <InsightBody insight={insight} />
    </Panel>
  );
}
