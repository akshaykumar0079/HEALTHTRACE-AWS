import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { useQuery } from "@tanstack/react-query";
import * as Tabs from "@radix-ui/react-tabs";
import * as Dialog from "@radix-ui/react-dialog";
import { AnimatePresence, motion } from "motion/react";
import { ArrowRight, BellRinging, Info, MagnifyingGlass, X } from "@phosphor-icons/react";
import { api } from "@/lib/api";
import { useLive } from "@/lib/live";
import type { Alert, AnomalyKind, Severity } from "@/lib/types";
import { KIND_LABEL, SEVERITIES, SEVERITY_HEX, ago, num, pct, serviceLabel, stamp, subjectOf } from "@/lib/format";
import { EmptyState, ErrorState, PageHeader, Panel, PanelHeader, Segmented, SeverityBadge, SkeletonRows, cx, inputClass } from "@/components/ui";
import { AlertRow } from "@/components/domain";

const tabClass =
  "h-9 rounded-[var(--radius-control)] px-3.5 text-[13px] font-medium text-fg-dim transition-colors hover:text-fg-muted data-[state=active]:bg-ink-750 data-[state=active]:text-fg data-[state=active]:shadow-[inset_0_0_0_1px_var(--hairline-strong)]";
const selectClass =
  "h-8 rounded-[var(--radius-control)] bg-ink-800 px-2.5 text-[12.5px] text-fg shadow-[inset_0_0_0_1px_var(--hairline-strong)] outline-none";

function useAlertHistory() {
  const live = useLive((s) => s.alerts);
  const query = useQuery({ queryKey: ["alerts", 1000], queryFn: () => api.alerts({ limit: 1000 }), refetchInterval: 20_000 });
  const merged = useMemo(() => {
    const seen = new Set<string>();
    const out: Alert[] = [];
    for (const a of [...live, ...(query.data ?? [])]) {
      const key = a.id != null ? `id:${a.id}` : `${a.ts}:${a.kind}:${a.service ?? a.user_id}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(a);
    }
    return out.sort((a, b) => b.ts.localeCompare(a.ts));
  }, [live, query.data]);
  return { alerts: merged, query };
}

function AlertDrawer({ alert, onClose }: { alert: Alert | null; onClose: () => void }) {
  const incidents = useLive((s) => s.incidents);
  const incident = alert?.incident_id != null ? incidents[alert.incident_id] : undefined;
  return (
    <Dialog.Root open={!!alert} onOpenChange={(o) => !o && onClose()}>
      <AnimatePresence>
        {alert && (
          <Dialog.Portal forceMount>
            <Dialog.Overlay asChild forceMount>
              <motion.div className="fixed inset-0 z-50 bg-ink-950/60 backdrop-blur-[2px]" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} />
            </Dialog.Overlay>
            <Dialog.Content asChild forceMount aria-describedby={undefined}>
              <motion.aside
                className="fixed inset-y-0 right-0 z-50 flex w-[min(460px,100vw)] flex-col border-l border-[var(--hairline)] bg-ink-900 shadow-[0_0_80px_-20px_rgb(0_0_0/0.9)]"
                initial={{ x: 40, opacity: 0 }}
                animate={{ x: 0, opacity: 1 }}
                exit={{ x: 40, opacity: 0 }}
                transition={{ duration: 0.35, ease: [0.16, 1, 0.3, 1] }}
              >
                <header className="flex items-start justify-between gap-4 border-b border-[var(--hairline)] p-5">
                  <div>
                    <SeverityBadge severity={alert.severity} />
                    <Dialog.Title className="mt-3 text-[18px] font-semibold tracking-tight text-fg">
                      {subjectOf(alert)}: {KIND_LABEL[alert.kind].toLowerCase()}
                    </Dialog.Title>
                    <p className="mt-1 font-mono text-[12px] text-fg-dim">{stamp(alert.ts)}{alert.id != null ? `  alert #${alert.id}` : ""}</p>
                  </div>
                  <Dialog.Close className="grid size-8 place-items-center rounded-lg text-fg-dim hover:bg-ink-750 hover:text-fg" aria-label="Close">
                    <X size={16} />
                  </Dialog.Close>
                </header>
                <div className="flex-1 space-y-6 overflow-y-auto p-5">
                  <p className="rounded-[12px] bg-ink-800 px-4 py-3 font-mono text-[12.5px] leading-relaxed text-fg-muted shadow-[inset_0_0_0_1px_var(--hairline)]">
                    {alert.explanation}
                  </p>
                  <section>
                    <h3 className="text-[12px] text-fg-dim">Measured values</h3>
                    <dl className="mt-2 grid grid-cols-2 gap-x-4 gap-y-3">
                      {Object.entries(alert.metrics)
                        .filter(([k, v]) => v !== null && !["service", "window_end", "malformed_lines"].includes(k))
                        .map(([k, v]) => (
                          <div key={k}>
                            <dt className="text-[11px] text-fg-dim">{k.replaceAll("_", " ")}</dt>
                            <dd className="font-mono text-[13px] text-fg">
                              {typeof v === "number" ? (k.includes("rate") || k === "baseline_mean" && alert.kind === "error_rate" ? pct(v, 2) : num(v, Number.isInteger(v) ? 0 : 2)) : String(v)}
                            </dd>
                          </div>
                        ))}
                    </dl>
                  </section>
                  <section>
                    <h3 className="text-[12px] text-fg-dim">Severity</h3>
                    <p className="mt-1.5 text-[13px] text-fg-muted">
                      {alert.score ? `Score ${alert.score.toFixed(3)} from deviation, service criticality and patient impact.` : "Rule based, from the HIPAA severity table."}
                    </p>
                  </section>
                  {alert.incident_id != null && (
                    <section className="rounded-[14px] bg-ink-850 p-4 shadow-[inset_0_0_0_1px_var(--hairline)]">
                      <h3 className="text-[12px] text-fg-dim">Anomaly</h3>
                      <p className="mt-1 text-[13.5px] text-fg">
                        #{alert.incident_id} {incident ? `is ${incident.state.toLowerCase()} with ${incident.alert_count} alerts` : ""}
                      </p>
                      <Link
                        to={`/app/incidents/${alert.incident_id}`}
                        className="mt-3 inline-flex items-center gap-1.5 text-[12.5px] font-medium text-signal"
                        onClick={onClose}
                      >
                        Investigate <ArrowRight size={13} />
                      </Link>
                    </section>
                  )}
                </div>
              </motion.aside>
            </Dialog.Content>
          </Dialog.Portal>
        )}
      </AnimatePresence>
    </Dialog.Root>
  );
}

function Feed() {
  const { alerts, query } = useAlertHistory();
  const incidents = useLive((s) => s.incidents);
  const fresh = useLive((s) => s.freshAlertIds);
  const services = useLive((s) => s.services);
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const [status, setStatus] = useState("all");
  const [service, setService] = useState("all");
  const [kind, setKind] = useState<AnomalyKind | "all">("all");
  const [text, setText] = useState("");
  const [selected, setSelected] = useState<Alert | null>(null);

  const filtered = alerts.filter((a) => {
    if (severity !== "all" && a.severity !== severity) return false;
    if (service !== "all" && (service === "hipaa" ? a.service !== null : a.service !== service)) return false;
    if (kind !== "all" && a.kind !== kind) return false;
    if (status !== "all") {
      const inc = a.incident_id != null ? incidents[a.incident_id] : undefined;
      const state = inc?.state ?? "RESOLVED";
      if (status === "open" ? state === "RESOLVED" : state !== "RESOLVED") return false;
    }
    if (text && !`${a.explanation} ${a.user_id ?? ""} ${a.service ?? ""}`.toLowerCase().includes(text.toLowerCase())) return false;
    return true;
  });

  return (
    <Panel>
      <div className="flex flex-wrap items-center gap-2.5 border-b border-[var(--hairline)] px-5 py-3.5">
        <div className="relative w-full sm:w-64">
          <MagnifyingGlass size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-fg-dim" />
          <label htmlFor="alert-search" className="sr-only">Search alerts</label>
          <input id="alert-search" value={text} onChange={(e) => setText(e.target.value)} placeholder="Search explanations" className={cx(inputClass, "h-8 pl-8")} />
        </div>
        <Segmented
          label="Severity"
          size="sm"
          value={severity}
          onChange={setSeverity}
          options={[{ value: "all" as const, label: "All" }, ...SEVERITIES.map((s) => ({ value: s, label: s.charAt(0) + s.slice(1).toLowerCase() }))]}
        />
        <label htmlFor="alert-status" className="sr-only">Status</label>
        <select id="alert-status" value={status} onChange={(e) => setStatus(e.target.value)} className={selectClass}>
          <option value="all">Any status</option>
          <option value="open">Anomaly active</option>
          <option value="resolved">Anomaly resolved</option>
        </select>
        <label htmlFor="alert-service" className="sr-only">Service</label>
        <select id="alert-service" value={service} onChange={(e) => setService(e.target.value)} className={selectClass}>
          <option value="all">All sources</option>
          {Object.keys(services).map((s) => <option key={s} value={s}>{serviceLabel(s)}</option>)}
          <option value="hipaa">HIPAA audit</option>
        </select>
        <label htmlFor="alert-kind" className="sr-only">Kind</label>
        <select id="alert-kind" value={kind} onChange={(e) => setKind(e.target.value as AnomalyKind | "all")} className={selectClass}>
          <option value="all">All kinds</option>
          {(Object.keys(KIND_LABEL) as AnomalyKind[]).map((k) => <option key={k} value={k}>{KIND_LABEL[k]}</option>)}
        </select>
        <span className="ml-auto font-mono text-[11.5px] text-fg-dim">{num(filtered.length)} alerts</span>
      </div>
      {query.isLoading && alerts.length === 0 ? (
        <SkeletonRows rows={8} />
      ) : query.error && alerts.length === 0 ? (
        <ErrorState error={query.error} onRetry={() => query.refetch()} />
      ) : filtered.length === 0 ? (
        <EmptyState icon={<BellRinging size={20} />} title={alerts.length ? "No alerts match these filters" : "No alerts yet"} body={alerts.length ? "Clear a filter to see more." : "Alerts appear here the moment a window deviates from its baseline."} />
      ) : (
        <div className="divide-y divide-[var(--hairline)]">
          {filtered.slice(0, 250).map((a) => (
            <div
              key={a.id ?? `${a.ts}-${a.kind}`}
              role="button"
              tabIndex={0}
              onClick={(e) => {
                e.preventDefault();
                setSelected(a);
              }}
              onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && setSelected(a)}
              className="cursor-pointer [&_a]:pointer-events-none"
            >
              <AlertRow alert={a} fresh={a.id != null && fresh.has(a.id)} />
            </div>
          ))}
        </div>
      )}
      <AlertDrawer alert={selected} onClose={() => setSelected(null)} />
    </Panel>
  );
}

function RuleRow({ name, condition, severity, notify }: { name: string; condition: string; severity: React.ReactNode; notify: string }) {
  return (
    <div className="grid gap-2 px-5 py-4 md:grid-cols-[1.1fr_1.6fr_1fr_1fr] md:items-center md:gap-4">
      <p className="text-[13.5px] font-medium text-fg">{name}</p>
      <p className="font-mono text-[12px] leading-relaxed text-fg-muted">{condition}</p>
      <div className="text-[12.5px] text-fg-muted">{severity}</div>
      <p className="text-[12.5px] text-fg-dim">{notify}</p>
    </div>
  );
}

function Rules() {
  const { data, isLoading, error, refetch } = useQuery({ queryKey: ["config"], queryFn: api.config, staleTime: 60_000 });
  if (isLoading) return <Panel><SkeletonRows rows={6} /></Panel>;
  if (error || !data) return <Panel><ErrorState error={error} onRetry={() => refetch()} /></Panel>;
  const { anomaly: a, severity: s, hipaa: h, window: w, incident: inc } = data.detection;
  const scored = `score bands: low < ${s.thresholds.low_max}, medium < ${s.thresholds.medium_max}, high < ${s.thresholds.high_max}, else critical`;
  return (
    <Panel>
      <PanelHeader
        title="Detection rules"
        description="The rules the backend is running now, read from config.yaml at startup."
      />
      <div className="mx-5 mb-4 flex gap-3 rounded-[12px] bg-ink-800 px-4 py-3 text-[12.5px] leading-relaxed text-fg-muted shadow-[inset_0_0_0_1px_var(--hairline)]">
        <Info size={16} className="mt-0.5 shrink-0 text-signal" />
        <p>
          Rules are code-reviewed configuration: edit <span className="font-mono text-fg">config.yaml</span> and restart the backend to change them. Creating or editing rules from this screen is not available in this release.
        </p>
      </div>
      <div className="hidden grid-cols-[1.1fr_1.6fr_1fr_1fr] gap-4 border-y border-[var(--hairline)] px-5 py-2.5 text-[11px] text-fg-dim md:grid">
        <span>Rule</span><span>Condition</span><span>Severity</span><span>Notification</span>
      </div>
      <div className="divide-y divide-[var(--hairline)]">
        <RuleRow
          name="Error rate spike"
          condition={`per service, ${w.size_seconds}s window every ${w.step_seconds}s: z ≥ ${a.error_rate_z_threshold}, errors ≥ ${a.error_rate_min_errors}, rate ≥ ${pct(a.error_rate_min_rate, 0)}`}
          severity={scored}
          notify="CloudWatch every alert, SNS on HIGH and CRITICAL"
        />
        <RuleRow
          name="Latency degradation"
          condition={`p95 latency z ≥ ${a.latency_z_threshold}, spread floor ${a.latency_min_std_ms}ms`}
          severity={scored}
          notify="CloudWatch every alert, SNS on HIGH and CRITICAL"
        />
        <RuleRow
          name="Bulk record access"
          condition={`distinct patients in 10 min > max(${h.bulk_multiplier_high} x user baseline, ${h.bulk_min_threshold})`}
          severity={<><SeverityBadge severity="HIGH" size="sm" /> above {h.bulk_multiplier_critical}x: <SeverityBadge severity="CRITICAL" size="sm" /></>}
          notify="SNS on open or escalation"
        />
        <RuleRow
          name="Bulk record export"
          condition={`exported records in 10 min > ${h.export_min_threshold}`}
          severity={<><SeverityBadge severity="MEDIUM" size="sm" /> above {h.export_critical_records}: <SeverityBadge severity="CRITICAL" size="sm" /></>}
          notify="SNS on CRITICAL"
        />
        <RuleRow
          name="Off-hours access"
          condition={`access outside ${h.off_hours_start} to ${h.off_hours_end} (${h.timezone})`}
          severity={<><SeverityBadge severity="MEDIUM" size="sm" /> above {h.off_hours_high_records} records: <SeverityBadge severity="HIGH" size="sm" /></>}
          notify="SNS on HIGH"
        />
        <RuleRow
          name="Cross-region access"
          condition="patient region differs from the user's region"
          severity={<><SeverityBadge severity="MEDIUM" size="sm" /> above {h.region_mismatch_medium_max} patients: <SeverityBadge severity="HIGH" size="sm" /></>}
          notify="SNS on HIGH"
        />
      </div>
      <p className="border-t border-[var(--hairline)] px-5 py-4 text-[12px] leading-relaxed text-fg-dim">
        Alerts with the same fingerprint are grouped into one anomaly. After an anomaly resolves, repeat notifications for it are suppressed for {inc.cooldown_minutes} minutes. Service anomalies resolve after {inc.service_auto_resolve_windows} normal windows, HIPAA anomalies after {inc.hipaa_auto_resolve_minutes} quiet minutes.
      </p>
    </Panel>
  );
}

function Delivery() {
  const { data, isLoading, error, refetch } = useQuery({ queryKey: ["aws-status"], queryFn: api.awsStatus, refetchInterval: 5000 });
  if (isLoading) return <Panel><SkeletonRows rows={4} /></Panel>;
  if (error || !data) return <Panel><ErrorState error={error} onRetry={() => refetch()} /></Panel>;
  const channels = [
    { name: "CloudWatch Logs", target: data.cloudwatch.log_group, s: data.cloudwatch },
    { name: "Amazon SNS", target: data.sns.topic_arn ?? "no topic configured", s: data.sns },
  ];
  return (
    <div className="grid gap-5 lg:grid-cols-2">
      {channels.map((c) => (
        <Panel key={c.name}>
          <PanelHeader title={c.name} description={<span className="font-mono">{c.target}</span>} actions={<Link to="/app/aws" className="text-[12px] font-medium text-fg-muted hover:text-signal">Configure</Link>} />
          <dl className="grid grid-cols-4 gap-4 border-y border-[var(--hairline)] px-5 py-4">
            {[["Sent", c.s.sent], ["Failed", c.s.failed], ["Skipped", c.s.skipped], ["Retries", c.s.retries]].map(([k, v]) => (
              <div key={k as string}>
                <dt className="text-[11.5px] text-fg-dim">{k}</dt>
                <dd className="mt-1 font-mono text-[18px] text-fg">{num(v as number)}</dd>
              </div>
            ))}
          </dl>
          {data.mode === "off" ? (
            <EmptyState title="AWS mode is off" body="Set AWS_MODE to mock or live to deliver notifications." className="py-10" />
          ) : c.s.recent.length === 0 ? (
            <EmptyState title="Nothing delivered yet" className="py-10" />
          ) : (
            <ul className="divide-y divide-[var(--hairline)]">
              {c.s.recent.slice(0, 8).map((r) => (
                <li key={`${r.ts}-${r.subject}`} className="flex items-center gap-3 px-5 py-2.5 text-[12.5px]">
                  <span className="w-14 font-mono text-[11px]" style={{ color: r.outcome === "sent" ? "#56dcc8" : r.outcome === "failed" ? SEVERITY_HEX.CRITICAL : SEVERITY_HEX.MEDIUM }}>
                    {r.outcome}
                  </span>
                  <span className="flex-1 truncate text-fg-muted">{r.subject}</span>
                  <span className="text-[11.5px] text-fg-dim">{ago(r.ts)}</span>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      ))}
    </div>
  );
}

export default function Alerts() {
  const [params, setParams] = useSearchParams();
  const tab = params.get("tab") ?? "feed";
  return (
    <div>
      <PageHeader title="Alerts" description="Every detection the pipeline emits, the rules that produce them, and where they were delivered." />
      <Tabs.Root value={tab} onValueChange={(v) => setParams((p) => { p.set("tab", v); return p; }, { replace: true })}>
        <Tabs.List aria-label="Alert views" className="mb-4 flex flex-wrap gap-1.5">
          <Tabs.Trigger value="feed" className={tabClass}>Live feed</Tabs.Trigger>
          <Tabs.Trigger value="rules" className={tabClass}>Rules</Tabs.Trigger>
          <Tabs.Trigger value="delivery" className={tabClass}>Delivery</Tabs.Trigger>
        </Tabs.List>
        <Tabs.Content value="feed" className="outline-none"><Feed /></Tabs.Content>
        <Tabs.Content value="rules" className="outline-none"><Rules /></Tabs.Content>
        <Tabs.Content value="delivery" className="outline-none"><Delivery /></Tabs.Content>
      </Tabs.Root>
    </div>
  );
}
