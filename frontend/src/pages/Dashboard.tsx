import { useMemo, useState } from "react";
import { Link, useNavigate } from "react-router";
import { motion, useReducedMotion } from "motion/react";
import { ArrowRight, ShieldCheck, Waveform } from "@phosphor-icons/react";
import TelemetryCanvas from "@/three/TelemetryCanvas";
import { activeIncidents, fleetRate, useLive } from "@/lib/live";
import { alertMarkers, useSeries, useSeriesAnchor } from "@/lib/series";
import {
  KIND_LABEL,
  SEVERITY_HEX,
  SIGNAL_HEX,
  compact,
  deviation,
  num,
  pct,
  subjectOf,
} from "@/lib/format";
import { AnimatedNumber, Beacon, Bezel, EmptyState, Panel, PanelHeader, Segmented, SkeletonRows, cx } from "@/components/ui";
import { TimeSeries } from "@/components/charts";
import { AlertRow, IncidentItem, LogLine, ServiceHealthRow } from "@/components/domain";

const reveal = (i: number, reduce: boolean | null) =>
  reduce
    ? {}
    : {
        initial: { opacity: 0, y: 18 },
        animate: { opacity: 1, y: 0 },
        transition: { duration: 0.7, delay: 0.06 * i, ease: [0.16, 1, 0.3, 1] as const },
      };

function Verdict() {
  const incidents = useLive((s) => s.incidents);
  const services = useLive((s) => s.services);
  const health = useLive((s) => s.health);
  const hydrated = useLive((s) => s.hydrated);
  const active = activeIncidents(incidents);
  const worst = active[0];
  const fleet = fleetRate(services);
  const eps = health ? health.throughput.app_eps + health.throughput.audit_eps : 0;
  const processed = health ? health.events_processed.app + health.events_processed.audit : 0;

  const headline = !hydrated
    ? "Connecting to the detection pipeline"
    : worst
      ? `${active.length} active ${active.length === 1 ? "anomaly" : "anomalies"}. ${subjectOf(worst)} is ${worst.peak_severity.toLowerCase()}.`
      : "Every service is within its expected range.";
  const detail = !hydrated
    ? "Waiting for the first snapshot from the backend."
    : worst
      ? `${KIND_LABEL[worst.kind]} detected against its learned baseline. Open the investigation for the evidence.`
      : "Error rates and latency sit inside each service's baseline band. Detection is watching every 5 second window.";
  const color = worst ? SEVERITY_HEX[worst.peak_severity] : SIGNAL_HEX;

  return (
    <div className="flex h-full flex-col justify-between gap-8 p-6 md:p-8">
      <div>
        <div className="flex items-center gap-2.5">
          {worst ? <Waveform size={18} style={{ color }} /> : <ShieldCheck size={18} style={{ color }} />}
          <span className="text-[12.5px] font-medium" style={{ color }}>
            {worst ? "Attention required" : "System healthy"}
          </span>
        </div>
        <h1 className="mt-4 max-w-[22ch] text-[28px] font-semibold leading-[1.12] tracking-[-0.025em] text-fg md:text-[34px]">
          {headline}
        </h1>
        <p className="mt-3 max-w-[48ch] text-[13.5px] leading-relaxed text-fg-muted">{detail}</p>
        {worst && (
          <Link
            to={`/app/incidents/${worst.id}`}
            className="group mt-5 inline-flex items-center gap-2 rounded-full py-1.5 pl-4 pr-1.5 text-[13px] font-medium text-ink-950 transition-transform active:scale-[0.98]"
            style={{ background: color }}
          >
            Investigate {subjectOf(worst)}
            <span className="grid size-7 place-items-center rounded-full bg-ink-950/15 transition-transform duration-300 group-hover:translate-x-0.5">
              <ArrowRight size={14} weight="bold" />
            </span>
          </Link>
        )}
      </div>

      <dl className="grid grid-cols-2 gap-x-6 gap-y-5 sm:grid-cols-4">
        <div>
          <dt className="text-[12px] text-fg-dim">Error rate</dt>
          <dd className="mt-1 font-mono text-[22px] tracking-tight text-fg">
            <AnimatedNumber value={fleet.rate * 100} format={(v) => `${v.toFixed(2)}%`} />
          </dd>
          <dd className="mt-0.5 text-[11.5px] text-fg-dim">
            {fleet.baseline != null ? `${deviation(fleet.rate, fleet.baseline)} vs baseline` : "baseline learning"}
          </dd>
        </div>
        <div>
          <dt className="text-[12px] text-fg-dim">Baseline</dt>
          <dd className="mt-1 font-mono text-[22px] tracking-tight text-fg">{fleet.baseline != null ? pct(fleet.baseline, 2) : "-"}</dd>
          <dd className="mt-0.5 text-[11.5px] text-fg-dim">traffic-weighted</dd>
        </div>
        <div>
          <dt className="text-[12px] text-fg-dim">Events / sec</dt>
          <dd className="mt-1 font-mono text-[22px] tracking-tight text-fg">
            <AnimatedNumber value={eps} format={(v) => v.toFixed(1)} />
          </dd>
          <dd className="mt-0.5 text-[11.5px] text-fg-dim">app and audit</dd>
        </div>
        <div>
          <dt className="text-[12px] text-fg-dim">Processed</dt>
          <dd className="mt-1 font-mono text-[22px] tracking-tight text-fg">{compact(processed)}</dd>
          <dd className="mt-0.5 text-[11.5px] text-fg-dim">
            lag {health?.event_lag_seconds != null ? `${num(Math.max(0, health.event_lag_seconds), 1)}s` : "-"}
          </dd>
        </div>
      </dl>
    </div>
  );
}

function RateChart() {
  const services = useLive((s) => s.services);
  const alerts = useLive((s) => s.alerts);
  const [service, setService] = useState<string>("all");
  const anchor = useSeriesAnchor();
  const { points, domain } = useSeries(service, 30, "error_rate", anchor);
  const markers = useMemo(() => alertMarkers(alerts, service, domain[0]), [alerts, service, domain]);
  const options = [
    { value: "all", label: "All" },
    ...Object.values(services).map((s) => ({ value: s.service, label: s.label.split(" ")[0] })),
  ];

  return (
    <Panel className="flex h-full flex-col">
      <PanelHeader
        title="Error rate against baseline"
        description={service === "all" ? "Fleet error rate with each service's learned baseline, weighted by traffic." : "Shaded band is the normal operating range: baseline mean plus or minus three standard deviations."}
        actions={
          <Link to="/app/monitor" className="text-[12px] font-medium text-fg-muted hover:text-signal">
            Live monitor
          </Link>
        }
      />
      <div className="overflow-x-auto px-5 pb-2">
        <Segmented label="Service" size="sm" value={service} options={options} onChange={setService} />
      </div>
      <div className="flex-1 px-3 pb-4 pt-2">
        {points.length > 1 ? (
          <TimeSeries
            points={points}
            markers={markers}
            xDomain={domain}
            height={260}
            yFormat={(v) => `${(v * 100).toFixed(v < 0.1 ? 1 : 0)}%`}
            ariaLabel="Error rate over the last 30 minutes"
          />
        ) : (
          <EmptyState title="Collecting windows" body="The first 5 second windows appear here as soon as log events arrive." className="py-20" />
        )}
      </div>
    </Panel>
  );
}

function ActiveAnomalies() {
  const incidents = useLive((s) => s.incidents);
  const hydrated = useLive((s) => s.hydrated);
  const active = activeIncidents(incidents);
  return (
    <Panel className="flex h-full flex-col">
      <PanelHeader
        title="Active anomalies"
        description={active.length ? "Ranked by peak severity." : undefined}
        actions={
          <Link to="/app/incidents" className="text-[12px] font-medium text-fg-muted hover:text-signal">
            All anomalies
          </Link>
        }
      />
      <div className="flex-1 divide-y divide-[var(--hairline)] overflow-y-auto">
        {!hydrated ? (
          <SkeletonRows rows={3} />
        ) : active.length === 0 ? (
          <EmptyState
            icon={<ShieldCheck size={20} />}
            title="No active anomalies"
            body="Your systems are currently operating within their expected range."
            className="py-16"
          />
        ) : (
          active.slice(0, 5).map((inc) => <IncidentItem key={inc.id} incident={inc} />)
        )}
      </div>
    </Panel>
  );
}

function ServiceHealth() {
  const services = useLive((s) => s.services);
  const series = useLive((s) => s.series);
  const rows = Object.values(services).sort((a, b) => (b.criticality ?? 0) - (a.criticality ?? 0));
  return (
    <Panel>
      <PanelHeader
        title="Service health"
        description="Latest 60 second window per service, ordered by clinical criticality."
        actions={
          <Link to="/app/services" className="text-[12px] font-medium text-fg-muted hover:text-signal">
            Service map
          </Link>
        }
      />
      <div className="hidden grid-cols-[minmax(170px,1.3fr)_repeat(4,minmax(70px,0.8fr))_110px] gap-x-4 px-5 pb-2 text-[11px] text-fg-dim md:grid">
        <span>Service</span>
        <span>Error rate</span>
        <span>Baseline</span>
        <span>Deviation</span>
        <span>p95 latency</span>
        <span className="text-right">15 min</span>
      </div>
      <div className="divide-y divide-[var(--hairline)] border-t border-[var(--hairline)]">
        {rows.length === 0 ? (
          <SkeletonRows rows={5} />
        ) : (
          rows.map((row) => (
            <ServiceHealthRow key={row.service} row={row} spark={(series[row.service] ?? []).slice(-180).map((p) => p.rate)} />
          ))
        )}
      </div>
    </Panel>
  );
}

function Streams() {
  const logs = useLive((s) => s.logs);
  const alerts = useLive((s) => s.alerts);
  const fresh = useLive((s) => s.freshAlertIds);
  return (
    <div className="grid gap-5 xl:grid-cols-[1.25fr_1fr]">
      <Panel className="flex flex-col">
        <PanelHeader
          title="Event stream"
          description="Every parsed log line, newest first. Patient IDs are masked."
          actions={
            <Link to="/app/logs" className="text-[12px] font-medium text-fg-muted hover:text-signal">
              Open explorer
            </Link>
          }
        />
        <div className="h-[340px] overflow-hidden border-t border-[var(--hairline)] py-1.5">
          {logs.length === 0 ? (
            <EmptyState title="No events yet" body="Log lines appear here as the tailer reads them." className="py-20" />
          ) : (
            logs.slice(0, 26).map((r) => <LogLine key={r.seq} record={r} />)
          )}
        </div>
      </Panel>
      <Panel className="flex flex-col">
        <PanelHeader
          title="Alert feed"
          description="Each detection, with the reason it fired."
          actions={
            <Link to="/app/alerts" className="text-[12px] font-medium text-fg-muted hover:text-signal">
              Alert center
            </Link>
          }
        />
        <div className="h-[340px] divide-y divide-[var(--hairline)] overflow-y-auto border-t border-[var(--hairline)]">
          {alerts.length === 0 ? (
            <EmptyState title="No alerts yet" body="Alerts appear the moment a window deviates from its baseline." className="py-20" />
          ) : (
            alerts.slice(0, 20).map((a) => <AlertRow key={`${a.id}-${a.ts}`} alert={a} fresh={a.id != null && fresh.has(a.id)} />)
          )}
        </div>
      </Panel>
    </div>
  );
}

export default function Dashboard() {
  const reduce = useReducedMotion();
  const navigate = useNavigate();
  const connection = useLive((s) => s.connection);
  const incidents = useLive((s) => s.incidents);
  const worst = activeIncidents(incidents)[0];

  return (
    <div className="space-y-5">
      <motion.div {...reveal(0, reduce)}>
        <Bezel coreClassName="overflow-hidden">
          <div className="grid lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]">
            <Verdict />
            <div className="relative h-[340px] border-t border-[var(--hairline)] lg:h-auto lg:min-h-[440px] lg:border-l lg:border-t-0">
              <TelemetryCanvas mode="dashboard" className="absolute inset-0" onSelect={(s) => navigate(`/app/services/${s}`)} />
              <div className="pointer-events-none absolute inset-x-0 bottom-0 flex items-center justify-between gap-4 bg-gradient-to-t from-ink-950/90 to-transparent px-5 pb-4 pt-12">
                <div className="flex items-center gap-2 text-[12px] text-fg-muted">
                  <Beacon color={connection === "live" ? (worst ? SEVERITY_HEX[worst.peak_severity] : SIGNAL_HEX) : "#627085"} size={7} />
                  System pulse
                </div>
                <p className="hidden text-[11.5px] text-fg-dim sm:block">
                  Particles are log events, tinted when they are errors. Select a service to open it.
                </p>
              </div>
            </div>
          </div>
        </Bezel>
      </motion.div>

      <div className={cx("grid gap-5 xl:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]")}>
        <motion.div {...reveal(1, reduce)}>
          <RateChart />
        </motion.div>
        <motion.div {...reveal(2, reduce)}>
          <ActiveAnomalies />
        </motion.div>
      </div>

      <motion.div {...reveal(3, reduce)}>
        <ServiceHealth />
      </motion.div>

      <motion.div {...reveal(4, reduce)}>
        <Streams />
      </motion.div>
    </div>
  );
}
