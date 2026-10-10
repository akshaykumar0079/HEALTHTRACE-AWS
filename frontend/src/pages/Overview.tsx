import { Link } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { ArrowRight } from "@phosphor-icons/react";
import { api } from "@/lib/api";
import { useLive } from "@/lib/live";
import type { ActivityItem, IncidentSummary } from "@/lib/types";
import { ago, compact, duration, num, stamp, STATE_LABEL } from "@/lib/format";
import { EmptyState, ErrorState, PageHeader, Panel, PanelHeader, SeverityBadge, Skeleton, SkeletonRows, cx } from "@/components/ui";
import { IncidentRows, OperatorNotice, useLiveIncidentRefresh } from "@/components/IncidentTable";
import { LogLine } from "@/components/domain";
import { SimulatedBadge, StatusStrip } from "@/components/StatusStrip";

function Card({ label, value, sub, tone, to }: { label: string; value: string; sub?: string; tone?: string; to?: string }) {
  const body = (
    <div className={cx("panel h-full p-4 transition-colors", to && "hover:bg-ink-800/60")}>
      <p className="text-[12px] text-fg-dim">{label}</p>
      <p className="mt-2 font-mono text-[28px] font-medium leading-none tracking-[-0.02em] tabular" style={{ color: tone ?? "var(--color-fg)" }}>
        {value}
      </p>
      {sub && <p className="mt-2 text-[11.5px] leading-snug text-fg-dim">{sub}</p>}
    </div>
  );
  return to ? <Link to={to} className="block rounded-[var(--radius-panel,16px)]">{body}</Link> : body;
}

function Cards({ summary }: { summary: IncidentSummary }) {
  const health = useLive((s) => s.health);
  const eps = health ? health.throughput.app_eps + health.throughput.audit_eps : null;
  const critical = summary.by_severity.CRITICAL;
  const high = summary.by_severity.HIGH;
  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
      <Card label="Active incidents" value={num(summary.active)} sub={`${summary.by_status.OPEN} new · ${summary.by_status.ACKNOWLEDGED} acknowledged · ${summary.by_status.INVESTIGATING} investigating`} to="/app/incidents" />
      <Card label="Critical" value={num(critical)} tone={critical ? "var(--color-sev-critical)" : undefined} sub="active, highest severity" to="/app/incidents?severity=CRITICAL" />
      <Card label="High" value={num(high)} tone={high ? "var(--color-sev-high)" : undefined} sub="active" to="/app/incidents?severity=HIGH" />
      <Card label="Needs acknowledgement" value={num(summary.unacknowledged_high)} sub="new high or critical incidents" to="/app/incidents?status=OPEN&severity=HIGH,CRITICAL" />
      <Card label="Pinned" value={num(summary.pinned)} sub="kept on your list" to="/app/pinned" />
      <Card
        label="Resolved, last 24h"
        value={num(summary.resolved_last_24h)}
        sub={summary.mean_time_to_resolve_seconds != null ? `mean time to resolve ${duration(summary.mean_time_to_resolve_seconds)}` : "no resolved incidents yet"}
        to="/app/history"
      />
      {eps != null && (
        <div className="col-span-full -mt-1 text-[12px] text-fg-dim">
          Pipeline: <span className="font-mono text-fg-muted">{eps.toFixed(1)}</span> events/sec ·{" "}
          <span className="font-mono text-fg-muted">{compact((health?.events_processed.app ?? 0) + (health?.events_processed.audit ?? 0))}</span> processed since start
        </div>
      )}
    </div>
  );
}

function PriorityTable() {
  useLiveIncidentRefresh();
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["incidents", "overview"],
    queryFn: () => api.incidentSearch({ status: "OPEN,ACKNOWLEDGED,INVESTIGATING", sort: "priority", limit: 8 }),
  });
  return (
    <Panel>
      <PanelHeader
        title="Needs attention"
        description="Active incidents ordered by severity, then risk score, then most recently seen."
        actions={<Link to="/app/incidents" className="inline-flex items-center gap-1 text-[12.5px] font-medium text-fg-muted hover:text-signal">All incidents <ArrowRight size={13} /></Link>}
      />
      {isLoading ? (
        <SkeletonRows rows={4} />
      ) : error ? (
        <ErrorState error={error} onRetry={() => refetch()} />
      ) : !data?.items.length ? (
        <EmptyState title="No active incidents" body="Detection is running and nothing needs attention." className="py-12" />
      ) : (
        <IncidentRows items={data.items} dense showActions={false} />
      )}
    </Panel>
  );
}

function LiveFeed() {
  const logs = useLive((s) => s.logs);
  const hydrated = useLive((s) => s.hydrated);
  return (
    <Panel className="flex flex-col">
      <PanelHeader
        title="Live events"
        description="Newest parsed log lines. Patient IDs are masked."
        actions={<Link to="/app/events" className="inline-flex items-center gap-1 text-[12.5px] font-medium text-fg-muted hover:text-signal">Open feed <ArrowRight size={13} /></Link>}
      />
      <div className="h-[300px] overflow-hidden border-t border-[var(--hairline)] py-1.5">
        {!hydrated ? (
          <SkeletonRows rows={6} />
        ) : logs.length === 0 ? (
          <EmptyState title="No events yet" body="Log lines appear here as the tailer reads them." className="py-14" />
        ) : (
          logs.slice(0, 14).map((r) => <LogLine key={r.seq} record={r} />)
        )}
      </div>
    </Panel>
  );
}

function Activity() {
  const { data, isLoading, error, refetch } = useQuery({ queryKey: ["activity"], queryFn: () => api.activity(10) });
  const verb = (a: ActivityItem) =>
    a.event_type === "opened" ? "Opened" : a.event_type === "escalated" ? `Escalated to ${a.severity ?? "higher severity"}`
    : a.event_type === "auto_resolved" ? "Resolved automatically" : a.event_type === "alert_attached" ? "New alert" : STATE_LABEL[a.event_type.toUpperCase() as keyof typeof STATE_LABEL] ?? a.event_type.replace("_", " ");
  return (
    <Panel className="flex flex-col">
      <PanelHeader title="Recent activity" description="Incident lifecycle changes, newest first." />
      <div className="h-[300px] divide-y divide-[var(--hairline)] overflow-y-auto border-t border-[var(--hairline)]">
        {isLoading ? <SkeletonRows rows={5} /> : error ? <ErrorState error={error} onRetry={() => refetch()} /> : !data?.length ? (
          <EmptyState title="No activity yet" body="Openings, escalations, pins and resolutions appear here." className="py-14" />
        ) : data.map((a) => (
          <Link key={a.id} to={`/app/incidents/${a.incident_id}`} className="flex items-start gap-3 px-5 py-2.5 text-[12.5px] hover:bg-ink-800/60">
            <span className="w-14 shrink-0 font-mono text-[11px] text-fg-dim" title={stamp(a.ts)}>{ago(a.ts)}</span>
            <span className="min-w-0 flex-1">
              <span className="block truncate text-fg">{a.title}</span>
              <span className="block text-fg-dim">{verb(a)} · <span className="font-mono">#{a.incident_id}</span></span>
            </span>
            {a.severity && <SeverityBadge severity={a.severity} size="sm" />}
          </Link>
        ))}
      </div>
    </Panel>
  );
}

export default function Overview() {
  useLiveIncidentRefresh();
  const { data: summary, isLoading, error, refetch } = useQuery({ queryKey: ["incident-summary"], queryFn: api.incidentSummary });
  return (
    <div className="space-y-5">
      <PageHeader
        title="Overview"
        description="What needs attention right now, computed from the incidents stored by the backend."
        actions={<SimulatedBadge />}
      />
      <StatusStrip />
      <OperatorNotice />
      {isLoading ? (
        <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">{Array.from({ length: 6 }, (_, i) => <Skeleton key={i} className="h-[104px]" />)}</div>
      ) : error || !summary ? (
        <ErrorState error={error} onRetry={() => refetch()} />
      ) : (
        <Cards summary={summary} />
      )}
      <PriorityTable />
      <div className="grid gap-5 xl:grid-cols-[1.4fr_1fr]">
        <LiveFeed />
        <Activity />
      </div>
    </div>
  );
}
