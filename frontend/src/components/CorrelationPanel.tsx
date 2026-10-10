import { useQuery } from "@tanstack/react-query";
import { Graph } from "@phosphor-icons/react";
import { api } from "@/lib/api";
import { stamp } from "@/lib/format";
import type { CorrelationGroup } from "@/lib/types";
import { EmptyState, ErrorState, Panel, PanelHeader, Skeleton } from "./ui";

const SOURCE_NAME: Record<string, string> = { app: "Application", auth: "Authentication", audit: "PHI audit", server: "Server", db_audit: "Database audit" };

function Group({ g }: { g: CorrelationGroup }) {
  return (
    <li className="px-5 py-4">
      <div className="flex flex-wrap items-center gap-2 text-[12px] text-fg-dim">
        <span className="font-mono">{g.group_id}</span>
        <span>{g.size} events from {g.sources.map((s) => SOURCE_NAME[s] ?? s).join(", ")}</span>
        {g.has_late_events && <span className="rounded-full bg-[#e3b35a1a] px-2 py-0.5 text-sev-medium">includes late-arriving events</span>}
      </div>
      <div className="mt-2">
        <p className="text-[12px] font-medium text-fg">Why these events are linked</p>
        <ul className="mt-1 list-disc space-y-0.5 pl-5 text-[12.5px] text-fg-muted">
          {g.why.map((w) => <li key={w}>{w}</li>)}
        </ul>
      </div>
      <ol className="mt-3 space-y-1 border-l border-[var(--hairline-strong)] pl-4">
        {g.events.map((e) => (
          <li key={e.id} className="text-[12.5px]">
            <span className="font-mono text-fg-dim">{stamp(e.ts)}</span>{" "}
            <span className="text-fg-muted">{SOURCE_NAME[e.source] ?? e.source}</span>{" "}
            <span className="text-fg">{e.message || e.action || e.outcome}</span>
            {e.late && <span className="ml-1.5 text-[11px] text-sev-medium">(arrived late)</span>}
          </li>
        ))}
      </ol>
    </li>
  );
}

export function CorrelationPanel({ incidentId }: { incidentId: number }) {
  const { data, error, isLoading, refetch } = useQuery({
    queryKey: ["correlation", incidentId],
    queryFn: () => api.correlation(incidentId),
  });
  return (
    <Panel>
      <PanelHeader
        title={<span className="inline-flex items-center gap-2"><Graph size={16} /> Linked events across systems</span>}
        description="Events are linked only when they share a key (the same user, request, host or record) and fall inside a documented time window. Similar timing alone never links events."
      />
      <div className="border-t border-[var(--hairline)]">
        {isLoading ? (
          <div className="p-5"><Skeleton className="h-24" /></div>
        ) : error ? (
          <ErrorState error={error} onRetry={() => refetch()} className="py-8" />
        ) : !data || data.groups.length === 0 ? (
          <EmptyState
            title="No linked events found"
            body={`${data?.event_count ?? 0} candidate events were checked against the correlation rules and none shared a key with this incident.${data?.limits ? ` ${data.limits}` : ""}`}
            className="py-10"
          />
        ) : (
          <>
            <ul className="divide-y divide-[var(--hairline)]">{data.groups.map((g) => <Group key={g.group_id} g={g} />)}</ul>
            {data.limits && <p className="border-t border-[var(--hairline)] px-5 py-3 text-[11.5px] text-fg-dim">{data.limits}</p>}
          </>
        )}
      </div>
    </Panel>
  );
}
