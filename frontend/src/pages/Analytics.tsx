import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { Severity } from "@/lib/types";
import { KIND_LABEL, SEVERITIES, SEVERITY_HEX, compact, duration, num, pct, serviceLabel } from "@/lib/format";
import { EmptyState, ErrorState, PageHeader, Panel, PanelHeader, Segmented, Skeleton } from "@/components/ui";
import { StackedColumns, TimeSeries } from "@/components/charts";
import { IncidentTrends } from "@/components/IncidentTrends";

const RANGES = [
  { value: "6", label: "6h" },
  { value: "24", label: "24h" },
  { value: "72", label: "3d" },
  { value: "168", label: "7d" },
];

const hourLabel = (key: string) => `${key.slice(5, 10).replace("-", "/")} ${key.slice(11, 13)}:00`;
const hourMs = (key: string) => new Date(`${key}:00:00Z`).getTime();

function Headline({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="px-5 py-5">
      <p className="text-[12px] text-fg-dim">{label}</p>
      <p className="mt-2 font-mono text-[26px] tracking-[-0.02em] text-fg">{value}</p>
      {sub && <p className="mt-1 text-[11.5px] text-fg-dim">{sub}</p>}
    </div>
  );
}

export default function Analytics() {
  const [range, setRange] = useState("24");
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["analytics", range],
    queryFn: () => api.analytics(Number(range)),
    refetchInterval: 30_000,
  });

  const header = (
    <PageHeader
      title="Analytics"
      description="How detection has behaved over time: volume, error trends, what fired, how severe it was and how long it took to recover."
      actions={<Segmented label="Range" value={range} options={RANGES} onChange={setRange} />}
    />
  );

  if (isLoading)
    return (
      <div>
        {header}
        <div className="grid gap-5 lg:grid-cols-2">{Array.from({ length: 4 }, (_, i) => <Skeleton key={i} className="h-72" />)}</div>
      </div>
    );
  if (error || !data)
    return (
      <div>
        {header}
        <Panel><ErrorState error={error} onRetry={() => refetch()} /></Panel>
      </div>
    );

  const totalAlerts = data.alerts_per_hour.reduce((s, r) => s + SEVERITIES.reduce((t, k) => t + (r[k] ?? 0), 0), 0);
  const events = data.volume_per_hour.reduce((s, r) => s + r.events, 0);
  const mttrAll = Object.values(data.mttr_seconds);
  const mttrMean = mttrAll.length ? mttrAll.reduce((s, m) => s + m.mean * m.count, 0) / mttrAll.reduce((s, m) => s + m.count, 0) : null;
  const sevTotal = SEVERITIES.reduce((s, k) => s + data.incidents.by_severity[k], 0);

  const ratePoints = data.volume_per_hour.map((r) => ({ t: hourMs(r.hour), v: r.error_rate }));
  const volumePoints = data.volume_per_hour.map((r) => ({ t: hourMs(r.hour), v: r.events / 3600 }));
  // Every hour in the range gets a column, so quiet hours read as quiet.
  const byHour = new Map(data.alerts_per_hour.map((r) => [r.hour, r]));
  const alertRows: { key: string; values: Record<string, number> }[] = [];
  const firstHour = Math.floor(new Date(data.since).getTime() / 3600_000) + 1;
  const lastHour = Math.max(firstHour, ...data.alerts_per_hour.map((r) => hourMs(r.hour) / 3600_000), Math.floor(Date.now() / 3600_000));
  for (let h = firstHour; h <= lastHour; h++) {
    const key = new Date(h * 3600_000).toISOString().slice(0, 13);
    const r = byHour.get(key);
    alertRows.push({ key, values: { LOW: r?.LOW ?? 0, MEDIUM: r?.MEDIUM ?? 0, HIGH: r?.HIGH ?? 0, CRITICAL: r?.CRITICAL ?? 0 } });
  }
  const sources = Object.entries(data.alerts_by_service).sort(
    (a, b) => SEVERITIES.reduce((s, k) => s + b[1][k], 0) - SEVERITIES.reduce((s, k) => s + a[1][k], 0),
  );

  return (
    <div className="space-y-5">
      {header}

      <Panel>
        <div className="grid grid-cols-2 divide-[var(--hairline)] md:grid-cols-5 md:divide-x">
          <Headline label="Events analysed" value={compact(events)} sub={`over ${RANGES.find((r) => r.value === range)?.label}`} />
          <Headline label="Alerts" value={num(totalAlerts)} sub={`${num(data.incidents.total)} anomalies after de-duplication`} />
          <Headline label="Active vs resolved" value={`${data.incidents.active} / ${data.incidents.resolved}`} sub="anomalies" />
          <Headline label="Mean time to resolve" value={mttrMean != null ? duration(mttrMean) : "-"} sub="opened to resolved" />
          <Headline label="Detection lag" value={data.detection_lag_seconds != null ? `${Math.max(0, data.detection_lag_seconds).toFixed(1)}s` : "-"} sub="log written to evaluated" />
        </div>
      </Panel>

      <div className="grid gap-5 xl:grid-cols-2">
        <Panel>
          <PanelHeader title="Error-rate trend" description="Hourly error rate across all services." />
          <div className="px-3 pb-4">
            {ratePoints.length > 1 ? (
              <TimeSeries points={ratePoints} height={220} showBand={false} yFormat={(v) => pct(v, 1)} ariaLabel="Hourly error rate" />
            ) : (
              <EmptyState title="Not enough history yet" body="Trends appear after two hours of stored windows." className="h-[220px]" />
            )}
          </div>
        </Panel>
        <Panel>
          <PanelHeader title="Event volume" description="Average events per second, per hour." />
          <div className="px-3 pb-4">
            {volumePoints.length > 1 ? (
              <TimeSeries points={volumePoints} height={220} showBand={false} color="#8ea3bf" yFormat={(v) => num(v, 1)} ariaLabel="Hourly event volume" />
            ) : (
              <EmptyState title="Not enough history yet" className="h-[220px]" />
            )}
          </div>
        </Panel>
      </div>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
        <Panel>
          <PanelHeader title="Anomaly frequency" description="Alerts per hour, stacked by severity." />
          <div className="px-5 pb-5">
            {alertRows.length ? (
              <StackedColumns
                rows={alertRows}
                keys={["LOW", "MEDIUM", "HIGH", "CRITICAL"]}
                colors={SEVERITY_HEX}
                height={220}
                label={hourLabel}
                ariaLabel="Alerts per hour by severity"
              />
            ) : (
              <EmptyState title="No alerts in this range" body="A quiet system produces an empty chart." className="h-[220px]" />
            )}
          </div>
        </Panel>
        <Panel>
          <PanelHeader title="Severity distribution" description="Peak severity of each anomaly." />
          <div className="px-5 pb-5">
            {sevTotal ? (
              <>
                <div className="flex h-3 overflow-hidden rounded-full">
                  {SEVERITIES.map((s) =>
                    data.incidents.by_severity[s] ? (
                      <div key={s} style={{ width: `${(data.incidents.by_severity[s] / sevTotal) * 100}%`, background: SEVERITY_HEX[s] }} />
                    ) : null,
                  )}
                </div>
                <ul className="mt-5 space-y-3">
                  {SEVERITIES.map((s: Severity) => (
                    <li key={s} className="flex items-center gap-3 text-[13px]">
                      <span className="size-2 rounded-full" style={{ background: SEVERITY_HEX[s] }} />
                      <span className="flex-1 text-fg-muted">{s.charAt(0) + s.slice(1).toLowerCase()}</span>
                      <span className="font-mono text-fg">{data.incidents.by_severity[s]}</span>
                      <span className="w-12 text-right font-mono text-fg-dim">{pct(data.incidents.by_severity[s] / sevTotal, 0)}</span>
                    </li>
                  ))}
                </ul>
              </>
            ) : (
              <EmptyState title="No anomalies in this range" className="h-[180px]" />
            )}
          </div>
        </Panel>
      </div>

      <div className="grid gap-5 xl:grid-cols-2">
        <Panel>
          <PanelHeader title="By source" description="Alerts per service or the HIPAA audit stream, and how fast they recovered." />
          {sources.length ? (
            <div className="overflow-x-auto border-t border-[var(--hairline)]">
              <table className="w-full min-w-[480px] text-left text-[12.5px]">
                <thead className="text-[11px] text-fg-dim">
                  <tr className="border-b border-[var(--hairline)]">
                    <th className="px-5 py-2.5 font-normal">Source</th>
                    {SEVERITIES.map((s) => <th key={s} className="px-2 py-2.5 text-right font-normal" style={{ color: SEVERITY_HEX[s] }}>{s.slice(0, 4)}</th>)}
                    <th className="px-5 py-2.5 text-right font-normal">MTTR</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--hairline)] font-mono">
                  {sources.map(([svc, counts]) => (
                    <tr key={svc} className="hover:bg-ink-800/60">
                      <td className="px-5 py-2.5 font-sans text-fg">{svc === "hipaa" ? "HIPAA audit" : serviceLabel(svc)}</td>
                      {SEVERITIES.map((s) => <td key={s} className="px-2 py-2.5 text-right text-fg-muted">{counts[s] || ""}</td>)}
                      <td className="px-5 py-2.5 text-right text-fg-muted">{data.mttr_seconds[svc] ? duration(data.mttr_seconds[svc].mean) : "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState title="No alerts in this range" className="py-12" />
          )}
        </Panel>
        <Panel>
          <PanelHeader title="Recurring patterns" description="Fingerprints that opened more than one anomaly in this range." />
          {data.recurring.length ? (
            <ul className="divide-y divide-[var(--hairline)] border-t border-[var(--hairline)]">
              {data.recurring.map((r) => {
                const [kind, subject] = r.fingerprint.split(":");
                return (
                  <li key={r.fingerprint} className="flex items-center gap-3 px-5 py-3 text-[13px]">
                    <span className="flex-1 text-fg">
                      {subject && !subject.startsWith("U-") ? serviceLabel(subject) : subject}
                      <span className="ml-2 text-fg-dim">{KIND_LABEL[kind as keyof typeof KIND_LABEL] ?? kind}</span>
                    </span>
                    <span className="font-mono text-fg">{r.count}x</span>
                  </li>
                );
              })}
            </ul>
          ) : (
            <EmptyState title="No recurring anomalies" body="Nothing has fired twice with the same fingerprint in this range." className="py-12" />
          )}
          <div className="border-t border-[var(--hairline)] px-5 py-4">
            <p className="text-[12px] text-fg-dim">Alert mix by kind</p>
            <div className="mt-3 flex flex-wrap gap-2">
              {Object.entries(data.alerts_by_kind).map(([k, n]) => (
                <span key={k} className="rounded-full bg-ink-800 px-3 py-1 text-[12px] text-fg-muted shadow-[inset_0_0_0_1px_var(--hairline)]">
                  {KIND_LABEL[k as keyof typeof KIND_LABEL] ?? k} <span className="ml-1 font-mono text-fg">{n}</span>
                </span>
              ))}
              {Object.keys(data.alerts_by_kind).length === 0 && <span className="text-[12px] text-fg-dim">none</span>}
            </div>
          </div>
        </Panel>
      </div>
      <IncidentTrends />
      <p className="text-[11.5px] text-fg-dim">
        Window metrics are retained for 24 hours; alert and anomaly history is kept in SQLite.
      </p>
    </div>
  );
}
