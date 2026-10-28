import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router";
import { api } from "@/lib/api";
import type { IncidentRef } from "@/lib/types";
import { duration, stamp } from "@/lib/format";
import { EmptyState, ErrorState, Panel, PanelHeader, SeverityBadge, SkeletonRows, StateBadge, cx } from "./ui";

function Candidate({ incident, score, scoreLabel, gap, reasons, cautions, tag }: {
  incident: IncidentRef;
  score: number;
  scoreLabel: string;
  gap: number | null;
  reasons: string[];
  cautions?: string[];
  tag?: string;
}) {
  return (
    <li className="px-5 py-4">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <Link
          to={`/app/incidents/${incident.id}`}
          className="text-[13.5px] font-medium text-fg hover:text-signal"
          aria-label={`Open incident ${incident.id}: ${incident.title}`}
        >
          #{incident.id} {incident.title}
        </Link>
        <SeverityBadge severity={incident.severity} size="sm" />
        <StateBadge state={incident.state} />
        {tag && (
          <span className="rounded-full bg-ink-800 px-2 py-0.5 text-[10.5px] font-medium uppercase tracking-wide text-fg-muted shadow-[inset_0_0_0_1px_var(--hairline)]">
            {tag}
          </span>
        )}
        <span className="ml-auto font-mono text-[12px] text-fg" title="Rule-based relevance, not a probability">
          {scoreLabel} {score.toFixed(2)}
        </span>
      </div>
      <p className="mt-1.5 text-[11.5px] text-fg-dim">
        Opened {stamp(incident.opened_at)}
        {gap !== null && (gap === 0 ? " · overlaps in time" : ` · ${duration(gap)} apart`)}
      </p>
      <ul className="mt-2 list-disc space-y-1 pl-5 text-[12.5px] leading-relaxed text-fg-muted">
        {reasons.map((r) => <li key={r}>{r}</li>)}
      </ul>
      {cautions?.length ? (
        <ul className="mt-2 list-disc space-y-1 pl-5 text-[12px] leading-relaxed text-[#e0b34a]">
          {cautions.map((c) => <li key={c}>{c}</li>)}
        </ul>
      ) : null}
    </li>
  );
}

export function RelatedIncidents({ incidentId }: { incidentId: number }) {
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["related", incidentId],
    queryFn: () => api.related(incidentId),
  });
  return (
    <Panel>
      <PanelHeader
        title="Possibly related incidents"
        description="Found by fixed rules (service, type, timing, dependencies). A match is a lead to check, not proof of a shared cause."
      />
      {isLoading ? (
        <SkeletonRows rows={3} className="border-t border-[var(--hairline)] px-5 py-4" />
      ) : error || !data ? (
        <ErrorState error={error ?? new Error("Related incidents are unavailable.")} onRetry={() => refetch()} />
      ) : data.related.length === 0 ? (
        <EmptyState
          title="No related incidents found"
          body={`Nothing among ${data.candidates_considered} nearby incident${data.candidates_considered === 1 ? "" : "s"} matched on enough signals.`}
          className="border-t border-[var(--hairline)] py-10"
        />
      ) : (
        <ul className={cx("divide-y divide-[var(--hairline)] border-t border-[var(--hairline)]")} aria-label="Related incidents">
          {data.related.map((r) => (
            <Candidate
              key={r.related_incident_id}
              incident={r.incident}
              score={r.score}
              scoreLabel="Match"
              gap={r.time_gap_seconds}
              reasons={r.reasons}
            />
          ))}
        </ul>
      )}
      {data?.candidates_truncated && (
        <p role="status" className="border-t border-[var(--hairline)] px-5 py-3 text-[11.5px] text-fg-dim">
          Many incidents were active nearby, so only the {data.candidates_considered} most recent were compared.
        </p>
      )}
    </Panel>
  );
}

export function DuplicateSuggestions({ incidentId }: { incidentId: number }) {
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["duplicates", incidentId],
    queryFn: () => api.duplicates(incidentId),
  });
  return (
    <Panel>
      <PanelHeader
        title="Possible duplicates"
        description="A stricter check than relatedness. For a person to review: nothing is merged, resolved or deleted automatically."
      />
      {isLoading ? (
        <SkeletonRows rows={2} className="border-t border-[var(--hairline)] px-5 py-4" />
      ) : error || !data ? (
        <ErrorState error={error ?? new Error("Duplicate suggestions are unavailable.")} onRetry={() => refetch()} />
      ) : data.duplicates.length === 0 ? (
        <EmptyState
          title="No likely duplicates"
          body={data.skipped_reason ?? "No other incident has the same type and service at nearly the same time."}
          className="border-t border-[var(--hairline)] py-10"
        />
      ) : (
        <ul className="divide-y divide-[var(--hairline)] border-t border-[var(--hairline)]" aria-label="Possible duplicates">
          {data.duplicates.map((d) => (
            <Candidate
              key={d.candidate_incident_id}
              incident={d.incident}
              score={d.score}
              scoreLabel="Similarity"
              gap={d.time_gap_seconds}
              reasons={d.reasons}
              cautions={d.cautions}
              tag={`${d.confidence} duplicate · review needed`}
            />
          ))}
        </ul>
      )}
    </Panel>
  );
}
