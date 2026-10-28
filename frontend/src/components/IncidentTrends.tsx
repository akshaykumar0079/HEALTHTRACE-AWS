import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { Severity } from "@/lib/types";
import { KIND_LABEL, SEVERITIES, SEVERITY_HEX, duration, num, serviceLabel } from "@/lib/format";
import { StackedColumns } from "./charts";
import { EmptyState, ErrorState, Panel, PanelHeader, Segmented, Skeleton } from "./ui";

const RANGES = [
  { value: "7", label: "7d" },
  { value: "30", label: "30d" },
  { value: "90", label: "90d" },
];

function Bars({ rows, label }: { rows: { key: string; label: string; count: number }[]; label: string }) {
  const top = Math.max(1, ...rows.map((r) => r.count));
  return (
    <ul className="space-y-2" aria-label={label}>
      {rows.map((r) => (
        <li key={r.key} className="grid grid-cols-[minmax(0,9rem)_1fr_2.5rem] items-center gap-3 text-[12.5px]">
          <span className="truncate text-fg-muted" title={r.label}>{r.label}</span>
          <span className="h-1.5 rounded-full bg-ink-800" aria-hidden>
            <span className="block h-full rounded-full bg-signal/70" style={{ width: `${(r.count / top) * 100}%` }} />
          </span>
          <span className="text-right font-mono text-fg">{r.count}</span>
        </li>
      ))}
    </ul>
  );
}

export function IncidentTrends() {
  const [range, setRange] = useState("30");
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["incident-trends", range],
    queryFn: () => api.incidentTrends({ days: Number(range) }),
    refetchInterval: 60_000,
  });
  const header = (
    <PanelHeader
      title="Incident trends"
      description="Counts of stored incidents opened in the range. Nothing here is estimated."
      actions={<Segmented label="Incident range" value={range} options={RANGES} onChange={setRange} />}
    />
  );
  if (isLoading)
    return <Panel>{header}<Skeleton className="m-5 h-56" /></Panel>;
  if (error || !data)
    return <Panel>{header}<ErrorState error={error ?? new Error("Incident trends are unavailable.")} onRetry={() => refetch()} /></Panel>;
  if (data.total === 0)
    return (
      <Panel>
        {header}
        <EmptyState title="No incidents in this range" body="Trends appear once incidents have been opened in the selected range." className="border-t border-[var(--hairline)] py-12" />
      </Panel>
    );

  const rows = data.series.map((p) => ({ key: p.bucket, values: Object.fromEntries(SEVERITIES.map((s) => [s, p[s]])) as Record<string, number> }));
  const res = data.resolution;
  return (
    <Panel>
      {header}
      <div className="grid gap-px border-t border-[var(--hairline)] bg-[var(--hairline)] sm:grid-cols-3">
        <div className="bg-ink-900 px-5 py-4">
          <p className="text-[12px] text-fg-dim">Incidents opened</p>
          <p className="mt-1.5 font-mono text-[24px] text-fg">{num(data.total)}</p>
        </div>
        <div className="bg-ink-900 px-5 py-4">
          <p className="text-[12px] text-fg-dim">Still open / resolved</p>
          <p className="mt-1.5 font-mono text-[24px] text-fg">{data.status.open} <span className="text-fg-dim">/</span> {data.status.resolved}</p>
        </div>
        <div className="bg-ink-900 px-5 py-4">
          <p className="text-[12px] text-fg-dim">Median time to resolve</p>
          {res.available ? (
            <>
              <p className="mt-1.5 font-mono text-[24px] text-fg">{duration(res.median_seconds)}</p>
              <p className="mt-1 text-[11.5px] text-fg-dim">p90 {duration(res.p90_seconds)} · {res.sample_size} resolved incidents</p>
            </>
          ) : (
            <>
              <p className="mt-1.5 font-mono text-[24px] text-fg-dim">n/a</p>
              <p className="mt-1 text-[11.5px] text-fg-dim">{res.reason}</p>
            </>
          )}
        </div>
      </div>
      <div className="border-t border-[var(--hairline)] px-5 py-5">
        <p className="text-[12px] text-fg-dim">Opened per {data.range.bucket}, by peak severity</p>
        <div className="mt-3">
          <StackedColumns
            rows={rows}
            keys={SEVERITIES}
            colors={SEVERITY_HEX}
            height={150}
            label={(k) => (k.length > 10 ? k.slice(5, 10).replace("-", "/") + ` ${k.slice(11, 13)}:00` : k.slice(5).replace("-", "/"))}
            ariaLabel={`Incidents opened per ${data.range.bucket}, ${data.total} in total`}
          />
        </div>
        <ul className="mt-3 flex flex-wrap gap-2" aria-label="By severity">
          {data.by_severity.filter((s) => s.count > 0).map((s) => (
            <li key={s.key} className="rounded-full bg-ink-800 px-3 py-1 text-[12px] text-fg-muted shadow-[inset_0_0_0_1px_var(--hairline)]">
              <span style={{ color: SEVERITY_HEX[s.key as Severity] }}>{s.key}</span> <span className="ml-1 font-mono text-fg">{s.count}</span>
            </li>
          ))}
        </ul>
      </div>
      <div className="grid gap-6 border-t border-[var(--hairline)] px-5 py-5 md:grid-cols-2">
        <div>
          <p className="mb-3 text-[12px] text-fg-dim">By service</p>
          <Bars label="Incidents by service" rows={data.by_service.map((r) => ({ key: r.key ?? "none", label: r.key ? serviceLabel(r.key) : "No service (user-scoped)", count: r.count }))} />
        </div>
        <div>
          <p className="mb-3 text-[12px] text-fg-dim">By anomaly type</p>
          <Bars label="Incidents by anomaly type" rows={data.by_kind.map((r) => ({ key: r.key, label: KIND_LABEL[r.key] ?? r.label, count: r.count }))} />
        </div>
      </div>
      <div className="border-t border-[var(--hairline)] px-5 py-5">
        <p className="text-[12px] text-fg-dim">Recurring patterns (same type and service, opened more than once)</p>
        {data.recurring.length ? (
          <ul className="mt-3 divide-y divide-[var(--hairline)]" aria-label="Recurring incident patterns">
            {data.recurring.map((r) => (
              <li key={`${r.kind}:${r.service ?? ""}`} className="flex items-center gap-3 py-2 text-[13px]">
                <span className="flex-1 text-fg">
                  {r.service ? serviceLabel(r.service) : "No service"}
                  <span className="ml-2 text-fg-dim">{KIND_LABEL[r.kind] ?? r.label}</span>
                </span>
                {r.reopen_count > 0 && <span className="text-[11.5px] text-fg-dim">{r.reopen_count} reopened</span>}
                <span className="font-mono text-fg">{r.count}x</span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="mt-2 text-[12.5px] text-fg-dim">Nothing opened twice with the same type and service in this range.</p>
        )}
        {data.resolved_without_valid_duration > 0 && (
          <p className="mt-4 text-[11.5px] text-fg-dim">
            {data.resolved_without_valid_duration} resolved incident(s) have no valid resolution time and are left out of the resolution figures.
          </p>
        )}
      </div>
    </Panel>
  );
}
