import { useMemo } from "react";
import { Link, useParams } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { motion, useReducedMotion } from "motion/react";
import {
  ArrowLeft,
  ArrowUpRight,
  BellSimpleRinging,
  CheckCircle,
  Circle,
  Cloud,
  Eye,
  Lightning,
  PushPin,
  Siren,
  XCircle,
} from "@phosphor-icons/react";
import { api } from "@/lib/api";
import { useLive } from "@/lib/live";
import type { Alert, IncidentDetail, IncidentEvent, LogRecord } from "@/lib/types";
import {
  KIND_LABEL,
  SEVERITY_HEX,
  SEVERITY_ORDER,
  STATE_LABEL,
  ago,
  clock,
  deviation,
  duration,
  isHipaaKind,
  ms,
  num,
  pct,
  serviceLabel,
  stamp,
  subjectOf,
} from "@/lib/format";
import { explain, nextSteps, scoreBreakdown, type ScoreBreakdown } from "@/lib/explain";
import { MIN_STD, Z_THRESHOLD } from "@/lib/series";
import { Bezel, EmptyState, ErrorState, Panel, PanelHeader, SeverityBadge, Skeleton, StateBadge, cx } from "@/components/ui";
import { TimeSeries, type TsPoint } from "@/components/charts";
import { IncidentActions, LogLine } from "@/components/domain";
import { RiskScore } from "@/components/IncidentTable";
import TelemetryCanvas from "@/three/TelemetryCanvas";

const EVENT_META: Record<IncidentEvent["event_type"], { label: string; icon: typeof Circle }> = {
  opened: { label: "Anomaly opened", icon: Siren },
  alert_attached: { label: "Alert attached", icon: Circle },
  escalated: { label: "Severity escalated", icon: Lightning },
  acknowledged: { label: "Acknowledged", icon: Eye },
  investigating: { label: "Investigation started", icon: Eye },
  pinned: { label: "Pinned", icon: Circle },
  unpinned: { label: "Unpinned", icon: Circle },
  resolved: { label: "Resolved by operator", icon: CheckCircle },
  auto_resolved: { label: "Resolved automatically", icon: CheckCircle },
  muted: { label: "Notifications changed", icon: BellSimpleRinging },
};

function peakAlert(alerts: Alert[]): Alert | undefined {
  return alerts.reduce<Alert | undefined>(
    (best, a) => (!best || SEVERITY_ORDER[a.severity] > SEVERITY_ORDER[best.severity] || (a.severity === best.severity && a.score > best.score) ? a : best),
    undefined,
  );
}

function Figure({ label, value, sub, color }: { label: string; value: string; sub?: string; color?: string }) {
  return (
    <div className="min-w-0">
      <p className="text-[12px] text-fg-dim">{label}</p>
      <p className="mt-1.5 font-mono text-[26px] font-medium leading-none tracking-[-0.02em] tabular md:text-[30px]" style={{ color: color ?? "var(--color-fg)" }}>
        {value}
      </p>
      {sub && <p className="mt-1.5 text-[11.5px] text-fg-dim">{sub}</p>}
    </div>
  );
}

function KeyFigures({ detail, alert }: { detail: IncidentDetail; alert: Alert }) {
  const m = alert.metrics;
  const color = SEVERITY_HEX[detail.incident.peak_severity];
  const num_ = (k: string) => (typeof m[k] === "number" ? (m[k] as number) : null);
  if (isHipaaKind(alert.kind)) {
    const main = num_("distinct_patients") ?? num_("records") ?? 0;
    return (
      <div className="grid grid-cols-2 gap-6 sm:grid-cols-4">
        <Figure label={alert.kind === "hipaa_bulk_export" || alert.kind === "hipaa_off_hours" ? "Records" : "Patients"} value={num(main)} color={color} />
        {num_("multiplier") != null && <Figure label="Versus baseline" value={`${(num_("multiplier") as number).toFixed(1)}x`} />}
        <Figure label="Window" value="10 min" sub="rolling, per user" />
        <Figure label="Alerts" value={num(detail.incident.alert_count)} sub={`over ${duration(elapsed(detail))}`} />
      </div>
    );
  }
  const latency = alert.kind === "latency_degradation";
  const current = latency ? num_("p95_latency_ms") : num_("error_rate");
  const base = num_("baseline_mean");
  const fmt = (v: number | null) => (v == null ? "-" : latency ? ms(v) : pct(v, 1));
  const patients = (num_("affected_patients_urgent") ?? 0) + (num_("affected_patients_routine") ?? 0);
  return (
    <div className="grid grid-cols-2 gap-6 sm:grid-cols-3 xl:grid-cols-6">
      <Figure label={latency ? "p95 latency" : "Current rate"} value={fmt(current)} color={color} />
      <Figure label="Baseline" value={fmt(base)} />
      <Figure label="Deviation" value={deviation(current, base)} color={color} />
      <Figure label="Window" value={`${num(num_("total") ?? 0)}`} sub="events in 60s" />
      <Figure label="z-score" value={num_("z") != null ? (num_("z") as number).toFixed(1) : "-"} sub={`threshold ${latency ? 4 : Z_THRESHOLD}`} />
      <Figure label="Patients affected" value={num(patients)} sub={`${num(num_("affected_patients_urgent") ?? 0)} urgent`} />
    </div>
  );
}

function elapsed(detail: IncidentDetail): number {
  const end = detail.incident.resolved_at ? new Date(detail.incident.resolved_at).getTime() : Date.now();
  return (end - new Date(detail.incident.opened_at).getTime()) / 1000;
}

function Why({ detail, alert }: { detail: IncidentDetail; alert: Alert }) {
  const e = explain(alert, detail.detection);
  const breakdown = scoreBreakdown(alert, detail.detection);
  const color = SEVERITY_HEX[alert.severity];
  const columns = [
    { ...e.current, tone: color },
    { ...e.normal, tone: "var(--color-steel)" },
    { ...e.rule, tone: "var(--color-fg)" },
  ];
  return (
    <Panel>
      <PanelHeader title="Why was this detected?" description="Current behaviour compared with learned normal behaviour, through the rule that fired." />
      <div className="grid border-t border-[var(--hairline)] md:grid-cols-3">
        {columns.map((c, i) => (
          <div key={c.label} className={cx("p-5", i > 0 && "border-t border-[var(--hairline)] md:border-l md:border-t-0")}>
            <p className="text-[12px] text-fg-dim">{c.label}</p>
            <p className="mt-2 font-mono text-[22px] tracking-tight" style={{ color: c.tone }}>{c.value}</p>
            <p className="mt-2 text-[12.5px] leading-relaxed text-fg-muted">{c.detail}</p>
          </div>
        ))}
      </div>
      <ul className="grid gap-x-6 gap-y-2 border-t border-[var(--hairline)] px-5 py-4 sm:grid-cols-2 lg:grid-cols-3">
        {e.checks.map((c) => (
          <li key={c.label} className="flex items-start gap-2 text-[12.5px]">
            {c.passed ? <CheckCircle size={16} className="mt-0.5 shrink-0 text-signal" weight="fill" /> : <XCircle size={16} className="mt-0.5 shrink-0 text-fg-dim" />}
            <span>
              <span className="text-fg">{c.label}</span>
              <span className="ml-1.5 font-mono text-fg-dim">{c.detail}</span>
            </span>
          </li>
        ))}
      </ul>
      {breakdown ? <ScoreBar b={breakdown} severityColor={color} /> : isHipaaKind(alert.kind) && (
        <p className="border-t border-[var(--hairline)] px-5 py-4 text-[12.5px] leading-relaxed text-fg-dim">
          HIPAA severity is rule based: each pattern maps to a fixed severity tier, escalating with volume.
        </p>
      )}
    </Panel>
  );
}

function ScoreBar({ b, severityColor }: { b: ScoreBreakdown; severityColor: string }) {
  const segments = [
    { label: "Low", from: 0, to: b.thresholds.low_max, color: SEVERITY_HEX.LOW },
    { label: "Medium", from: b.thresholds.low_max, to: b.thresholds.medium_max, color: SEVERITY_HEX.MEDIUM },
    { label: "High", from: b.thresholds.medium_max, to: b.thresholds.high_max, color: SEVERITY_HEX.HIGH },
    { label: "Critical", from: b.thresholds.high_max, to: 1, color: SEVERITY_HEX.CRITICAL },
  ];
  return (
    <div className="border-t border-[var(--hairline)] px-5 py-5">
      <p className="text-[12px] text-fg-dim">Severity score</p>
      <p className="mt-2 font-mono text-[12.5px] leading-relaxed text-fg-muted">
        <span className="text-fg">{b.deviation.toFixed(2)}</span> deviation
        <span className="mx-1.5 text-fg-dim">x</span>(
        {b.weights.criticality} x <span className="text-fg">{b.criticality.toFixed(2)}</span> criticality
        <span className="mx-1.5 text-fg-dim">+</span>
        {b.weights.patient} x <span className="text-fg">{b.patientFactor.toFixed(2)}</span> patient impact)
        <span className="mx-1.5 text-fg-dim">=</span>
        <span style={{ color: severityColor }}>{b.score.toFixed(3)}</span>
      </p>
      <div className="relative mt-4 h-2">
        <div className="flex h-full overflow-hidden rounded-full">
          {segments.map((s) => (
            <div key={s.label} style={{ width: `${(s.to - s.from) * 100}%`, background: s.color, opacity: 0.28 }} />
          ))}
        </div>
        <div
          className="absolute top-1/2 size-3.5 -translate-x-1/2 -translate-y-1/2 rounded-full ring-4 ring-ink-850"
          style={{ left: `${Math.min(1, b.score) * 100}%`, background: severityColor }}
          aria-label={`Score ${b.score.toFixed(2)}`}
        />
      </div>
      <div className="relative mt-2 h-4 text-[10.5px] text-fg-dim">
        {segments.map((s) => (
          <span key={s.label} className="absolute" style={{ left: `${s.from * 100}%` }}>{s.label}</span>
        ))}
      </div>
      <p className="mt-2 text-[12px] leading-relaxed text-fg-dim">
        Deviation is z divided by {b.weights.zCap}, capped at 1. Patient impact counts urgent patients twice, over a cap of {b.weights.patientCap}. A small spike on a critical, patient-facing service can outrank a large one on batch work.
      </p>
    </div>
  );
}

function IncidentChart({ detail }: { detail: IncidentDetail }) {
  const inc = detail.incident;
  const service = inc.service;
  const opened = new Date(inc.opened_at).getTime();
  const closed = inc.resolved_at ? new Date(inc.resolved_at).getTime() : Date.now();
  const latency = inc.kind === "latency_degradation";
  const span = Math.min(1440, Math.ceil((Date.now() - opened) / 60000) + 12);
  const { data, isLoading, error } = useQuery({
    queryKey: ["incident-metrics", service, span, inc.resolved_at ? "closed" : Math.floor(Date.now() / 15000)],
    queryFn: () => api.metrics(service as string, span),
    enabled: !!service,
  });
  const domain: [number, number] = [opened - 10 * 60_000, Math.max(closed + 3 * 60_000, opened + 5 * 60_000)];
  const points: TsPoint[] = useMemo(
    () =>
      (data ?? [])
        .map((m) => {
          const t = new Date(m.window_end).getTime();
          if (latency) return { t, v: m.p95_latency_ms };
          const std = m.baseline_std != null ? Math.max(m.baseline_std, MIN_STD) : null;
          return {
            t,
            v: m.error_rate,
            mean: m.baseline_mean ?? null,
            lo: m.baseline_mean != null && std != null ? m.baseline_mean - Z_THRESHOLD * std : null,
            hi: m.baseline_mean != null && std != null ? m.baseline_mean + Z_THRESHOLD * std : null,
          };
        })
        .filter((p) => p.t >= domain[0] && p.t <= domain[1]),
    [data, latency, domain[0], domain[1]], // eslint-disable-line react-hooks/exhaustive-deps
  );
  const markers = detail.alerts.map((a) => ({ t: new Date(a.ts).getTime(), severity: a.severity, label: a.explanation }));

  if (!service) return null;
  return (
    <Panel>
      <PanelHeader
        title={latency ? "p95 latency around the anomaly" : "Error rate around the anomaly"}
        description="Ten minutes before it opened through its resolution. Dots mark each alert."
      />
      <div className="px-3 pb-4">
        {isLoading ? (
          <Skeleton className="h-[260px]" />
        ) : error ? (
          <ErrorState error={error} />
        ) : points.length < 2 ? (
          <EmptyState title="Window history is no longer retained" body="Metrics are kept for 24 hours." className="h-[260px]" />
        ) : (
          <TimeSeries
            points={points}
            markers={markers}
            xDomain={domain}
            height={260}
            yFormat={latency ? ms : (v) => `${(v * 100).toFixed(v < 0.1 ? 1 : 0)}%`}
            showBand={!latency}
            color={SEVERITY_HEX[inc.peak_severity]}
            ariaLabel="Metric around the anomaly window"
          />
        )}
      </div>
    </Panel>
  );
}

function Timeline({ events }: { events: IncidentEvent[] }) {
  // Collapse runs of attached alerts so the lifecycle stays readable.
  const rows: (IncidentEvent & { count: number })[] = [];
  for (const e of events) {
    const last = rows[rows.length - 1];
    if (last && last.event_type === "alert_attached" && e.event_type === "alert_attached") {
      last.count += 1;
      continue;
    }
    rows.push({ ...e, count: 1 });
  }
  return (
    <Panel>
      <PanelHeader title="Timeline" description="Every state change, as recorded by the incident engine." />
      <ol className="relative px-5 pb-5">
        <span className="absolute bottom-7 left-[31px] top-2 w-px bg-[var(--hairline-strong)]" aria-hidden />
        {rows.map((e) => {
          const meta = EVENT_META[e.event_type];
          const color = e.severity ? SEVERITY_HEX[e.severity] : e.event_type.includes("resolved") ? "#56dcc8" : "#93a1b3";
          return (
            <li key={`${e.id}-${e.ts}`} className="relative flex gap-4 py-2.5">
              <span className="relative z-10 grid size-6 shrink-0 place-items-center rounded-full bg-ink-850 ring-1 ring-[var(--hairline-strong)]" style={{ color }}>
                <meta.icon size={13} weight="bold" />
              </span>
              <div className="min-w-0">
                <p className="text-[13px] text-fg">
                  {e.count > 1 ? `${e.count} alerts attached` : meta.label}
                  {e.severity && e.event_type !== "alert_attached" && <span className="ml-2 font-mono text-[11px]" style={{ color }}>{e.severity}</span>}
                </p>
                <p className="font-mono text-[11.5px] text-fg-dim">{stamp(e.ts)}{e.detail ? `  ${e.detail}` : ""}</p>
              </div>
            </li>
          );
        })}
      </ol>
    </Panel>
  );
}

function RelatedLogs({ detail }: { detail: IncidentDetail }) {
  const inc = detail.incident;
  const q = inc.service ? `service:${inc.service} level:ERROR` : `user:${inc.user_id}`;
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["related-logs", q],
    queryFn: () => api.logs(q, 40),
    refetchInterval: inc.state === "RESOLVED" ? false : 5000,
  });
  const events: LogRecord[] = data?.events ?? [];
  return (
    <Panel className="flex flex-col">
      <PanelHeader
        title="Related log events"
        description={inc.service ? `Recent errors from ${serviceLabel(inc.service)}.` : `Recent record access by ${inc.user_id}.`}
        actions={
          <Link to={`/app/logs?q=${encodeURIComponent(q)}`} className="inline-flex items-center gap-1 text-[12px] font-medium text-fg-muted hover:text-signal">
            Open in logs <ArrowUpRight size={12} />
          </Link>
        }
      />
      <div className="max-h-[320px] overflow-y-auto border-t border-[var(--hairline)] py-1.5">
        {isLoading ? <Skeleton className="m-5 h-40" /> : error ? <ErrorState error={error} onRetry={() => refetch()} /> : events.length === 0 ? (
          <EmptyState title="No matching events in the recent buffer" body="The explorer keeps the most recent 5,000 events in memory." className="py-10" />
        ) : (
          events.map((r) => <LogLine key={r.seq} record={r} />)
        )}
      </div>
    </Panel>
  );
}

function Delivery({ detail }: { detail: IncidentDetail }) {
  const { data } = useQuery({ queryKey: ["aws-status"], queryFn: api.awsStatus, refetchInterval: 10_000 });
  const inc = detail.incident;
  const eligible = inc.peak_severity === "HIGH" || inc.peak_severity === "CRITICAL";
  const snsEvents = data?.sns.recent.filter((r) => r.subject.startsWith(`incident #${inc.id} `)) ?? [];
  return (
    <Panel>
      <PanelHeader title="AWS delivery" description="Where this anomaly's notifications were sent." />
      <dl className="divide-y divide-[var(--hairline)] border-t border-[var(--hairline)] text-[12.5px]">
        <div className="flex items-start justify-between gap-4 px-5 py-3">
          <dt className="flex items-center gap-2 text-fg-muted"><Cloud size={15} /> CloudWatch Logs</dt>
          <dd className="text-right text-fg">
            {data?.mode === "off" ? <span className="text-fg-dim">AWS mode off</span> : `${detail.alerts.length} alert${detail.alerts.length === 1 ? "" : "s"} to ${data?.cloudwatch.log_group ?? "log group"}`}
          </dd>
        </div>
        <div className="flex items-start justify-between gap-4 px-5 py-3">
          <dt className="flex items-center gap-2 text-fg-muted"><BellSimpleRinging size={15} /> SNS</dt>
          <dd className="max-w-[60%] text-right">
            {data?.mode === "off" ? (
              <span className="text-fg-dim">AWS mode off</span>
            ) : !eligible ? (
              <span className="text-fg-dim">Not sent. SNS pages on HIGH and CRITICAL only.</span>
            ) : snsEvents.length ? (
              snsEvents.map((e) => (
                <span key={e.ts} className={cx("block", e.outcome === "sent" ? "text-signal" : "text-sev-high")}>
                  {e.outcome} {ago(e.ts)}{e.error ? `: ${e.error}` : ""}
                </span>
              ))
            ) : (
              <span className="text-fg-dim">No delivery recorded this session{inc.muted_until ? " (muted)" : ""}.</span>
            )}
          </dd>
        </div>
      </dl>
    </Panel>
  );
}

export default function Investigation() {
  const { id } = useParams();
  const incidentId = Number(id);
  const reduce = useReducedMotion();
  const liveIncident = useLive((s) => s.incidents[incidentId]);
  const config = useQuery({ queryKey: ["config"], queryFn: api.config, staleTime: 60_000 });
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["incident", incidentId, liveIncident?.alert_count, liveIncident?.state],
    queryFn: () => api.incident(incidentId),
    enabled: Number.isFinite(incidentId),
    placeholderData: (prev) => prev,
  });

  if (isLoading) return <div className="space-y-4"><Skeleton className="h-64" /><Skeleton className="h-48" /></div>;
  if (error || !data) return <ErrorState error={error ?? new Error("Anomaly not found.")} onRetry={() => refetch()} />;

  const detail: IncidentDetail = liveIncident ? { ...data, incident: { ...data.incident, ...liveIncident } } : data;
  const inc = detail.incident;
  const alert = peakAlert(detail.alerts);
  const color = SEVERITY_HEX[inc.peak_severity];
  const steps = nextSteps(inc, config.data);

  const fade = (i: number) =>
    reduce ? {} : { initial: { opacity: 0, y: 16 }, animate: { opacity: 1, y: 0 }, transition: { duration: 0.6, delay: 0.05 * i, ease: [0.16, 1, 0.3, 1] as const } };

  return (
    <div className="space-y-5">
      <Link to="/app/incidents" className="inline-flex items-center gap-1.5 text-[12.5px] text-fg-dim hover:text-fg">
        <ArrowLeft size={14} /> Incidents
      </Link>

      <motion.div {...fade(0)}>
        <Bezel coreClassName="overflow-hidden">
          <div className="grid lg:grid-cols-[minmax(0,1fr)_380px]">
            <div className="p-6 md:p-8">
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={inc.peak_severity} />
                <StateBadge state={inc.state} />
                <span className="font-mono text-[12px] text-fg-dim">#{inc.id}</span>
                <span className="inline-flex items-center gap-1.5 text-[12px] text-fg-muted">Risk score <RiskScore incident={inc} /></span>
                {inc.pinned && <span className="inline-flex items-center gap-1 rounded-full bg-[#56dcc812] px-2.5 py-1 text-[11px] font-medium text-signal"><PushPin size={11} weight="fill" /> Pinned</span>}
              </div>
              <h1 className="mt-4 text-[28px] font-semibold leading-[1.1] tracking-[-0.025em] text-fg md:text-[36px]">
                {subjectOf(inc)}: {KIND_LABEL[inc.kind].toLowerCase()}
              </h1>
              <p className="mt-2 text-[13px] text-fg-muted">
                {STATE_LABEL[inc.state]} for {duration(elapsed(detail))}. Opened {stamp(inc.opened_at)}
                {inc.acknowledged_at && `, acknowledged ${clock(inc.acknowledged_at)}`}
                {inc.resolved_at && `, resolved ${clock(inc.resolved_at)}`}.
              </p>
              {alert && <p className="mt-4 max-w-[70ch] rounded-[12px] bg-ink-800 px-4 py-3 font-mono text-[12.5px] leading-relaxed text-fg-muted shadow-[inset_0_0_0_1px_var(--hairline)]">{alert.explanation}</p>}
              <div className="mt-6">
                <IncidentActions incident={inc} />
              </div>
            </div>
            {inc.service ? (
              <div className="relative h-[260px] border-t border-[var(--hairline)] lg:h-auto lg:border-l lg:border-t-0">
                <TelemetryCanvas mode="map" focus={inc.service} className="absolute inset-0" />
                <p className="pointer-events-none absolute bottom-3 left-4 text-[11.5px] text-fg-dim">Zoomed to {serviceLabel(inc.service)}</p>
              </div>
            ) : (
              <div className="grid place-items-center border-t border-[var(--hairline)] p-8 lg:border-l lg:border-t-0" style={{ background: `radial-gradient(circle at 50% 40%, ${color}1a, transparent 65%)` }}>
                <div className="text-center">
                  <p className="font-mono text-[34px] tracking-tight text-fg">{inc.user_id}</p>
                  <p className="mt-1 text-[12px] text-fg-dim">user under review</p>
                </div>
              </div>
            )}
          </div>
          {alert && (
            <div className="border-t border-[var(--hairline)] p-6 md:px-8">
              <KeyFigures detail={detail} alert={alert} />
            </div>
          )}
        </Bezel>
      </motion.div>

      {alert && <motion.div {...fade(1)}><Why detail={detail} alert={alert} /></motion.div>}

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)]">
        <motion.div {...fade(2)} className="space-y-5">
          <IncidentChart detail={detail} />
          <RelatedLogs detail={detail} />
        </motion.div>
        <motion.div {...fade(3)} className="space-y-5">
          <Panel>
            <PanelHeader title="What to do next" />
            <ol className="space-y-3 border-t border-[var(--hairline)] px-5 py-4">
              {steps.map((s, i) => (
                <li key={s} className="flex gap-3 text-[13px] leading-relaxed text-fg-muted">
                  <span className="grid size-5 shrink-0 place-items-center rounded-full bg-ink-750 font-mono text-[10.5px] text-fg">{i + 1}</span>
                  {s}
                </li>
              ))}
            </ol>
          </Panel>
          <Timeline events={detail.events} />
          <Delivery detail={detail} />
        </motion.div>
      </div>

      <Panel>
        <PanelHeader
          title="Evidence"
          description="Masked log events captured when this incident was detected. They are stored with the incident and stay after the live buffer has moved on."
        />
        {detail.evidence.length === 0 ? (
          <EmptyState title="No evidence stored" body="Evidence is captured for incidents detected while this version is running." className="py-10" />
        ) : (
          <div className="overflow-x-auto border-t border-[var(--hairline)]">
            <table className="w-full min-w-[640px] text-left text-[12.5px]">
              <thead className="text-[11px] text-fg-dim">
                <tr className="border-b border-[var(--hairline)]">
                  <th className="px-5 py-2.5 font-normal">Time</th>
                  <th className="px-3 py-2.5 font-normal">Level</th>
                  <th className="px-3 py-2.5 font-normal">Source</th>
                  <th className="px-5 py-2.5 font-normal">Event</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--hairline)]">
                {detail.evidence.map((e) => (
                  <tr key={e.id} className="hover:bg-ink-800/60">
                    <td className="whitespace-nowrap px-5 py-2.5 font-mono text-fg-dim">{stamp(e.ts)}</td>
                    <td className="px-3 py-2.5 font-mono text-fg-muted">{String(e.record.level ?? "")}</td>
                    <td className="px-3 py-2.5 text-fg-muted">{String(e.record.service ?? e.record.user_id ?? "")}</td>
                    <td className="px-5 py-2.5 text-fg-muted">
                      {String(e.record.msg ?? "")}
                      {e.record.status != null && <span className="ml-2 font-mono text-fg-dim">{String(e.record.status)} · {String(e.record.latency_ms ?? "-")}ms</span>}
                      {e.record.patient_id != null && <span className="ml-2 font-mono text-fg-dim">{String(e.record.patient_id)}</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <Panel>
        <PanelHeader title="Alert history" description={`${detail.alerts.length} alert${detail.alerts.length === 1 ? "" : "s"} fingerprinted to this anomaly, newest first.`} />
        <div className="overflow-x-auto border-t border-[var(--hairline)]">
          <table className="w-full min-w-[640px] text-left text-[12.5px]">
            <thead className="text-[11px] text-fg-dim">
              <tr className="border-b border-[var(--hairline)]">
                <th className="px-5 py-2.5 font-normal">Time</th>
                <th className="px-3 py-2.5 font-normal">Severity</th>
                <th className="px-3 py-2.5 font-normal">Score</th>
                <th className="px-5 py-2.5 font-normal">Explanation</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--hairline)]">
              {detail.alerts.slice(0, 100).map((a) => (
                <tr key={a.id ?? a.ts} className="hover:bg-ink-800/60">
                  <td className="whitespace-nowrap px-5 py-2.5 font-mono text-fg-dim">{stamp(a.ts)}</td>
                  <td className="px-3 py-2.5"><SeverityBadge severity={a.severity} size="sm" /></td>
                  <td className="px-3 py-2.5 font-mono text-fg-muted">{a.score ? a.score.toFixed(3) : "rule"}</td>
                  <td className="px-5 py-2.5 text-fg-muted">{a.explanation}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}
