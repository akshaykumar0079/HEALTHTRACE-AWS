import { Link } from "react-router";
import { motion, useReducedMotion } from "motion/react";
import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { ArrowRight, BellSlash, CheckCircle, Eye, MagnifyingGlass, PushPin } from "@phosphor-icons/react";
import type { Alert, Incident, LogRecord, ServiceRow } from "@/lib/types";
import {
  KIND_LABEL,
  SEVERITY_HEX,
  TONE_HEX,
  TONE_LABEL,
  ago,
  clock,
  deviation,
  duration,
  isHipaaKind,
  ms,
  pct,
  serviceTone,
  subjectOf,
} from "@/lib/format";
import { ApiError, api } from "@/lib/api";
import { ConfirmDialog } from "./Confirm";
import { useLive } from "@/lib/live";
import { toast } from "@/app/toast";
import { Button, SeverityBadge, StateBadge, cx } from "./ui";
import { Sparkline } from "./charts";

// -- incident actions ---------------------------------------------------------------

export function useIncidentActions() {
  const qc = useQueryClient();
  const upsert = useLive((s) => s.upsertIncident);
  const refresh = (inc: Incident) => {
    upsert(inc);
    void qc.invalidateQueries({ queryKey: ["incidents"] });
    void qc.invalidateQueries({ queryKey: ["incident-summary"] });
    void qc.invalidateQueries({ queryKey: ["incident", inc.id] });
  };
  const onError = (verb: string) => (e: unknown) => {
    const forbidden = e instanceof ApiError && (e.status === 401 || e.status === 403);
    toast.error(
      `Could not ${verb}`,
      forbidden ? "Operator access is required. Add the operator token under Settings, API access." : e instanceof Error ? e.message : undefined,
    );
  };
  const ack = useMutation({
    mutationFn: api.ack,
    onSuccess: (inc) => {
      refresh(inc);
      toast.success("Acknowledged", `Incident #${inc.id} is now owned. Detection keeps attaching new alerts.`);
    },
    onError: onError("acknowledge"),
  });
  const investigate = useMutation({
    mutationFn: api.investigate,
    onSuccess: (inc) => {
      refresh(inc);
      toast.success("Investigating", `Incident #${inc.id} is marked as being worked on.`);
    },
    onError: onError("start investigating"),
  });
  const resolve = useMutation({
    mutationFn: api.resolve,
    onSuccess: (inc) => {
      refresh(inc);
      toast.success("Resolved", `Incident #${inc.id} moved to History after ${duration(inc.mttr_seconds)}.`);
    },
    onError: onError("resolve"),
  });
  const mute = useMutation({
    mutationFn: ({ id, minutes }: { id: number; minutes: number }) => api.mute(id, minutes),
    onSuccess: (inc) => {
      refresh(inc);
      toast.success(inc.muted_until ? "Notifications muted" : "Notifications unmuted",
        inc.muted_until ? "Notifications are paused for this incident. Detection continues." : undefined);
    },
    onError: onError("mute"),
  });
  const pin = useMutation({
    mutationFn: ({ id, pinned }: { id: number; pinned: boolean }) => (pinned ? api.pin(id) : api.unpin(id)),
    onSuccess: (inc) => {
      refresh(inc);
      toast.success(inc.pinned ? "Pinned" : "Unpinned", inc.pinned ? `Incident #${inc.id} is on your Pinned list. Severity is unchanged.` : undefined);
    },
    onError: onError("change the pin"),
  });
  return { ack, investigate, resolve, mute, pin };
}

export function PinButton({ incident, className }: { incident: Incident; className?: string }) {
  const { pin } = useIncidentActions();
  return (
    <button
      type="button"
      aria-pressed={incident.pinned}
      aria-label={incident.pinned ? `Unpin incident ${incident.id}` : `Pin incident ${incident.id}`}
      title={incident.pinned ? "Pinned. Click to unpin" : "Pin to keep this incident on your Pinned list"}
      disabled={pin.isPending}
      onClick={() => pin.mutate({ id: incident.id, pinned: !incident.pinned })}
      className={cx(
        "grid size-8 place-items-center rounded-[var(--radius-control)] transition-colors hover:bg-ink-750 disabled:opacity-50",
        incident.pinned ? "text-signal" : "text-fg-dim hover:text-fg-muted",
        className,
      )}
    >
      <PushPin size={16} weight={incident.pinned ? "fill" : "regular"} />
    </button>
  );
}

export function IncidentActions({ incident, compact }: { incident: Incident; compact?: boolean }) {
  const { ack, investigate, resolve, mute } = useIncidentActions();
  const [confirming, setConfirming] = useState(false);
  if (incident.state === "RESOLVED") return <PinButton incident={incident} />;
  const muted = incident.muted_until && new Date(incident.muted_until).getTime() > Date.now();
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      <PinButton incident={incident} />
      {incident.state === "OPEN" && (
        <Button size="sm" variant="secondary" busy={ack.isPending} onClick={() => ack.mutate(incident.id)} icon={<Eye size={14} />}>
          Acknowledge
        </Button>
      )}
      {(incident.state === "OPEN" || incident.state === "ACKNOWLEDGED") && (
        <Button size="sm" variant="secondary" busy={investigate.isPending} onClick={() => investigate.mutate(incident.id)} icon={<MagnifyingGlass size={14} />}>
          Investigate
        </Button>
      )}
      <Button size="sm" variant="secondary" onClick={() => setConfirming(true)} icon={<CheckCircle size={14} />}>
        Resolve
      </Button>
      {!compact && (
        <Button
          size="sm"
          variant="ghost"
          busy={mute.isPending}
          onClick={() => mute.mutate({ id: incident.id, minutes: muted ? 0 : 30 })}
          icon={<BellSlash size={14} />}
          title={muted ? "Resume notifications" : "Pause notifications for 30 minutes"}
        >
          {muted ? "Unmute" : "Mute 30m"}
        </Button>
      )}
      <ConfirmDialog
        open={confirming}
        onOpenChange={setConfirming}
        title={`Resolve incident #${incident.id}?`}
        body={<>It moves to History and stops absorbing alerts. If the problem comes back, a new incident opens. Nothing is deleted: the evidence and timeline stay searchable.</>}
        confirmLabel="Resolve incident"
        busy={resolve.isPending}
        onConfirm={() => resolve.mutate(incident.id, { onSettled: () => setConfirming(false) })}
      />
    </div>
  );
}

// -- incidents ------------------------------------------------------------------------

export function IncidentItem({ incident, now = Date.now() }: { incident: Incident; now?: number }) {
  const color = SEVERITY_HEX[incident.peak_severity];
  const open = incident.state !== "RESOLVED";
  const age = ((incident.resolved_at ? new Date(incident.resolved_at).getTime() : now) - new Date(incident.opened_at).getTime()) / 1000;
  return (
    <article className="group relative flex gap-4 px-5 py-4 transition-colors hover:bg-ink-800/60">
      <span className="absolute inset-y-4 left-0 w-[2px] rounded-full" style={{ background: open ? color : "var(--color-ink-600)" }} aria-hidden />
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={incident.peak_severity} size="sm" />
          <StateBadge state={incident.state} />
          {incident.muted_until && new Date(incident.muted_until).getTime() > now && (
            <span className="inline-flex items-center gap-1 text-[11px] text-fg-dim"><BellSlash size={12} /> muted</span>
          )}
        </div>
        <Link to={`/app/incidents/${incident.id}`} className="mt-2 block text-[14px] font-medium tracking-tight text-fg hover:text-signal">
          {incident.title}
        </Link>
        <p className="mt-1 text-[12px] text-fg-dim">
          <span className="font-mono">#{incident.id}</span>
          <span className="mx-1.5">opened {ago(incident.opened_at, now)}</span>
          <span className="font-mono">{incident.alert_count}</span> alert{incident.alert_count === 1 ? "" : "s"}
          <span className="mx-1.5">{open ? "running" : "lasted"} {duration(age)}</span>
        </p>
      </div>
      <div className="flex shrink-0 flex-col items-end justify-between gap-2">
        <Link
          to={`/app/incidents/${incident.id}`}
          className="inline-flex items-center gap-1 text-[12px] font-medium text-fg-muted transition-colors group-hover:text-signal"
        >
          Investigate <ArrowRight size={13} />
        </Link>
        <IncidentActions incident={incident} compact />
      </div>
    </article>
  );
}

// -- alerts ---------------------------------------------------------------------------

export function AlertRow({ alert, fresh }: { alert: Alert; fresh?: boolean }) {
  const reduce = useReducedMotion();
  const body = (
    <>
      <span className="w-[62px] shrink-0 font-mono text-[11.5px] text-fg-dim tabular">{clock(alert.ts)}</span>
      <SeverityBadge severity={alert.severity} size="sm" />
      <div className="min-w-0 flex-1">
        <p className="truncate text-[12.5px] text-fg">
          <span className="font-medium">{subjectOf(alert)}</span>
          <span className="text-fg-dim"> {KIND_LABEL[alert.kind]}</span>
        </p>
        <p className="mt-0.5 line-clamp-2 text-[12px] leading-relaxed text-fg-muted">{alert.explanation}</p>
      </div>
    </>
  );
  const className = cx(
    "flex items-start gap-3 px-5 py-3 transition-colors hover:bg-ink-800/60",
    fresh && "animate-arrive",
  );
  const inner = alert.incident_id ? (
    <Link to={`/app/incidents/${alert.incident_id}`} className={className}>{body}</Link>
  ) : (
    <div className={className}>{body}</div>
  );
  if (!fresh || reduce) return inner;
  return (
    <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5, ease: [0.16, 1, 0.3, 1] }}>
      {inner}
    </motion.div>
  );
}

// -- services -------------------------------------------------------------------------

export function ServiceHealthRow({ row, spark }: { row: ServiceRow; spark: number[] }) {
  const tone = serviceTone(row);
  const color = TONE_HEX[tone];
  return (
    <Link
      to={`/app/services/${row.service}`}
      className="group grid grid-cols-[1fr_auto] items-center gap-x-4 gap-y-2 px-5 py-3.5 transition-colors hover:bg-ink-800/60 md:grid-cols-[minmax(170px,1.3fr)_repeat(4,minmax(70px,0.8fr))_110px]"
    >
      <div className="flex min-w-0 items-center gap-3">
        <span className="relative grid size-8 shrink-0 place-items-center rounded-full" style={{ background: `${color}14` }}>
          <span className="size-2 rounded-full" style={{ background: color }} />
        </span>
        <div className="min-w-0">
          <p className="truncate text-[13.5px] font-medium text-fg group-hover:text-signal">{row.label}</p>
          <p className="text-[11.5px]" style={{ color: tone === "healthy" || tone === "learning" ? "var(--color-fg-dim)" : color }}>
            {TONE_LABEL[tone]}
            {row.active_incidents > 0 && ` · ${row.active_incidents} active`}
          </p>
        </div>
      </div>
      <Metric label="Error rate" value={pct(row.error_rate, 2)} accent={tone !== "healthy" && tone !== "learning" ? color : undefined} className="text-right md:text-left" />
      <Metric label="Baseline" value={row.baseline_mean != null ? pct(row.baseline_mean, 2) : "learning"} className="hidden md:block" />
      <Metric label="Deviation" value={deviation(row.error_rate, row.baseline_mean)} className="hidden md:block" />
      <Metric label="p95" value={ms(row.p95_latency_ms)} className="hidden md:block" />
      <div className="hidden justify-end md:flex">
        <Sparkline values={spark} color={color} ariaLabel={`${row.label} error rate, last 15 minutes`} />
      </div>
    </Link>
  );
}

function Metric({ label, value, accent, className }: { label: string; value: string; accent?: string; className?: string }) {
  return (
    <div className={className}>
      <p className="text-[10.5px] text-fg-dim md:hidden">{label}</p>
      <p className="font-mono text-[13px] tabular" style={{ color: accent ?? "var(--color-fg)" }}>{value}</p>
    </div>
  );
}

// -- logs -------------------------------------------------------------------------------

const LEVEL_COLOR: Record<string, string> = {
  ERROR: "var(--color-sev-critical)",
  WARN: "var(--color-sev-medium)",
  INFO: "var(--color-fg-dim)",
};

export function LogLine({ record, onSelect, selected }: { record: LogRecord; onSelect?: (r: LogRecord) => void; selected?: boolean }) {
  const subject = record.type === "app" ? record.service : record.user_id;
  return (
    <button
      type="button"
      onClick={() => onSelect?.(record)}
      className={cx(
        "grid w-full grid-cols-[64px_44px_1fr] items-baseline gap-3 px-4 py-1.5 text-left font-mono text-[11.5px] transition-colors md:grid-cols-[64px_44px_110px_1fr_auto]",
        selected ? "bg-ink-750" : "hover:bg-ink-800/70",
      )}
    >
      <span className="text-fg-dim tabular">{clock(record.ts)}</span>
      <span style={{ color: LEVEL_COLOR[record.level] }}>{record.level}</span>
      <span className="hidden truncate text-fg-muted md:block">{subject}</span>
      <span className="truncate text-fg">{record.msg}</span>
      <span className="hidden text-fg-dim md:block">
        {record.type === "app" ? `${record.status} ${record.latency_ms}ms` : record.action}
      </span>
    </button>
  );
}

export function isHipaa(kind: Incident["kind"]) {
  return isHipaaKind(kind);
}
