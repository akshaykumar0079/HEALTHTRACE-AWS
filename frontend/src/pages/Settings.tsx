import { useEffect, useState, type ReactNode } from "react";
import { useLocation } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { Info, ShieldCheck } from "@phosphor-icons/react";
import { api, getOperatorToken, setOperatorToken } from "@/lib/api";
import { useLive } from "@/lib/live";
import { pct } from "@/lib/format";
import { Button, ErrorState, Field, PageHeader, Panel, Skeleton, cx, inputClass } from "@/components/ui";
import { toast } from "@/app/toast";
import { NotificationSettings } from "@/components/NotificationSettings";
import { AwsIntegration } from "@/components/AwsIntegration";

const SECTIONS = [
  ["general", "General"],
  ["notifications", "Notifications"],
  ["detection", "Detection"],
  ["baseline", "Baseline"],
  ["severity", "Severity"],
  ["hipaa", "HIPAA access"],
  ["realtime", "Real-time"],
  ["aws", "AWS"],
  ["access", "API access"],
  ["routing", "Alert routing"],
] as const;

function Section({ id, title, description, children }: { id: string; title: string; description?: string; children: ReactNode }) {
  return (
    <Panel as="section">
      <div id={id} className="scroll-mt-24 px-6 pb-2 pt-5">
        <h2 className="text-[15px] font-medium tracking-tight text-fg">{title}</h2>
        {description && <p className="mt-1 max-w-[70ch] text-[12.5px] leading-relaxed text-fg-dim">{description}</p>}
      </div>
      <div className="px-6 pb-5">{children}</div>
    </Panel>
  );
}

function Rows({ rows }: { rows: [string, ReactNode, string?][] }) {
  return (
    <dl className="divide-y divide-[var(--hairline)]">
      {rows.map(([k, v, hint]) => (
        <div key={k} className="grid gap-1 py-3 sm:grid-cols-[220px_140px_1fr] sm:items-baseline sm:gap-4">
          <dt className="text-[13px] text-fg-muted">{k}</dt>
          <dd className="font-mono text-[13px] text-fg">{v}</dd>
          {hint && <dd className="text-[12px] leading-relaxed text-fg-dim">{hint}</dd>}
        </div>
      ))}
    </dl>
  );
}

function OperatorToken({ required }: { required: boolean }) {
  const [value, setValue] = useState(getOperatorToken);
  const [saved, setSaved] = useState(!!getOperatorToken());
  return (
    <form
      className="max-w-lg space-y-4"
      onSubmit={(e) => {
        e.preventDefault();
        setOperatorToken(value.trim());
        setSaved(!!value.trim());
        toast.success(value.trim() ? "Operator token saved for this tab" : "Operator token cleared");
      }}
    >
      <Field
        label="Operator token"
        htmlFor="op-token"
        hint={required
          ? "This backend requires a token for pinning, status changes, notification settings, demo and AWS test actions. It is kept in this tab's session storage only."
          : "This backend does not require a token (OPERATOR_TOKEN is unset). Set one in production."}
      >
        <input
          id="op-token"
          type="password"
          autoComplete="off"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          className={inputClass}
          placeholder={required ? "Paste the operator token" : "Not required"}
        />
      </Field>
      <div className="flex items-center gap-3">
        <Button type="submit" variant="primary" size="sm" icon={<ShieldCheck size={14} />}>Save for this session</Button>
        {saved && <span className="text-[12px] text-signal">A token is set</span>}
      </div>
    </form>
  );
}

export default function Settings() {
  const { data, isLoading, error, refetch } = useQuery({ queryKey: ["config"], queryFn: api.config });
  const health = useLive((s) => s.health);
  const location = useLocation();
  const [active, setActive] = useState<string>("general");

  useEffect(() => {
    const id = location.hash.slice(1);
    if (id) window.setTimeout(() => document.getElementById(id)?.scrollIntoView({ behavior: "smooth", block: "start" }), 100);
  }, [location.hash, data]);

  useEffect(() => {
    const els = SECTIONS.map(([id]) => document.getElementById(id)).filter((el): el is HTMLElement => !!el);
    const io = new IntersectionObserver(
      (entries) => {
        const top = entries.filter((e) => e.isIntersecting).sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top)[0];
        if (top) setActive(top.target.id);
      },
      { rootMargin: "-80px 0px -60% 0px" },
    );
    els.forEach((el) => io.observe(el));
    return () => io.disconnect();
  }, [data]);

  if (isLoading) return <Skeleton className="h-96" />;
  if (error || !data) return <ErrorState error={error} onRetry={() => refetch()} />;
  const d = data.detection;
  const dep = data.deployment;

  return (
    <div>
      <PageHeader title="Settings" description="Notifications you can change here; detection and deployment settings are shown read-only." />
      <div className="mb-5 flex gap-3 rounded-[14px] bg-ink-850 px-5 py-4 text-[12.5px] leading-relaxed text-fg-muted shadow-[inset_0_0_0_1px_var(--hairline)]">
        <Info size={17} className="mt-0.5 shrink-0 text-signal" />
        <p>
          Notification settings below are editable and saved in the database. Detection settings come from <span className="font-mono text-fg">config.yaml</span> and deployment settings from environment variables, both read at startup. They are shown read-only so the numbers you see are the numbers in force.
        </p>
      </div>
      <div className="grid gap-8 lg:grid-cols-[180px_minmax(0,1fr)]">
        <nav aria-label="Settings sections" className="hidden lg:block">
          <ul className="sticky top-24 space-y-0.5">
            {SECTIONS.map(([id, label]) => (
              <li key={id}>
                <a
                  href={`#${id}`}
                  className={cx(
                    "block rounded-[var(--radius-control)] px-3 py-1.5 text-[13px] transition-colors",
                    active === id ? "bg-ink-750 text-fg" : "text-fg-dim hover:text-fg-muted",
                  )}
                >
                  {label}
                </a>
              </li>
            ))}
          </ul>
        </nav>
        <div className="space-y-5">
          <Section id="general" title="General">
            <Rows rows={[
              ["Project", dep.project_name, "PROJECT_NAME"],
              ["Environment", dep.environment, "ENVIRONMENT"],
              ["Demo scenarios", dep.demo_mode ? "enabled" : "disabled", "DEMO_MODE: enables scenario injection from the dashboard"],
            ]} />
          </Section>
          <Section id="notifications" title="Notifications" description="Email alerts for serious incidents. Changes apply immediately and are kept across restarts.">
            <NotificationSettings />
          </Section>
          <Section id="detection" title="Detection" description="Every service gets a sliding window over event time; each window is compared with its baseline.">
            <Rows rows={[
              ["Sliding window", `${d.window.size_seconds}s`, "events considered per evaluation"],
              ["Evaluation step", `${d.window.step_seconds}s`, "a new window is emitted this often"],
              ["Error-rate sensitivity", `z ≥ ${d.anomaly.error_rate_z_threshold}`, "standard deviations above baseline"],
              ["Minimum errors", d.anomaly.error_rate_min_errors, "per window, to rule out noise"],
              ["Minimum error rate", pct(d.anomaly.error_rate_min_rate, 0), "per window"],
              ["Spread floor", pct(d.anomaly.min_std, 0), "smallest standard deviation assumed"],
              ["Latency sensitivity", `z ≥ ${d.anomaly.latency_z_threshold}`, `spread floor ${d.anomaly.latency_min_std_ms}ms`],
            ]} />
          </Section>
          <Section id="baseline" title="Baseline" description="An exponentially weighted mean and variance per service and hour of day, learned only from windows judged normal.">
            <Rows rows={[
              ["Smoothing (alpha)", d.baseline.alpha, "lower is steadier against slow drifts"],
              ["Warm-up", `${d.baseline.warmup_windows} windows`, "before an hour's baseline is trusted"],
              ["Fallback", "all-hours baseline", "used while an hour bucket warms up"],
              ["Refresh", "every window", "baseline persisted every 60s and on shutdown"],
            ]} />
          </Section>
          <Section id="severity" title="Severity" description="score = deviation x (criticality weight x criticality + patient weight x patient impact).">
            <Rows rows={[
              ["Deviation cap", `z / ${d.severity.deviation_z_cap}`, "deviation saturates at 1"],
              ["Criticality weight", d.severity.criticality_weight],
              ["Patient-impact weight", d.severity.patient_factor_weight, `impact = (2 x urgent + routine) / ${d.severity.patient_factor_cap}`],
              ["Thresholds", `${d.severity.thresholds.low_max} / ${d.severity.thresholds.medium_max} / ${d.severity.thresholds.high_max}`, "low, medium, high upper bounds; above is critical"],
              ...Object.entries(d.services).map(([name, s]) => [`${s.label ?? name} criticality`, s.criticality] as [string, ReactNode]),
            ]} />
          </Section>
          <Section id="hipaa" title="HIPAA access" description="A second detector watching the access audit log per user.">
            <Rows rows={[
              ["Business hours", `${d.hipaa.off_hours_start} to ${d.hipaa.off_hours_end}`, d.hipaa.timezone],
              ["Bulk access floor", d.hipaa.bulk_min_threshold, `distinct patients in 10 min; high above ${d.hipaa.bulk_multiplier_high}x baseline, critical above ${d.hipaa.bulk_multiplier_critical}x`],
              ["Bulk export floor", d.hipaa.export_min_threshold, `critical above ${d.hipaa.export_critical_records} records`],
              ["Re-alert interval", `${d.hipaa.realert_seconds}s`, "an unchanged pattern re-alerts at most this often"],
            ]} />
          </Section>
          <Section id="realtime" title="Real-time" description="Live updates use a WebSocket; the dashboard reconnects on its own.">
            <Rows rows={[
              ["Transport", "WebSocket /ws", "snapshot on connect, then metric, alert, anomaly and log messages"],
              ["Heartbeat", "10s", "clients reconnect if 25s pass without a message"],
              ["Reconnect", "exponential backoff", "0.5s doubling to 10s, with jitter; fresh snapshot each time"],
              ["Connected clients", health?.ws_clients ?? "-"],
            ]} />
          </Section>
          <Section id="aws" title="AWS">
            <AwsIntegration />
            <Rows rows={[
              ["Mode", dep.aws_mode, "AWS_MODE: off, mock or live"],
              ["Details", "see the AWS integration page", "region, log group, topic and delivery status"],
            ]} />
          </Section>
          <Section id="access" title="API access" description="Read endpoints are open to anyone who can reach the app; put sign-in (ALB with Cognito) in front of it in production.">
            <OperatorToken required={dep.operator_token_required} />
          </Section>
          <Section id="routing" title="Alert routing" description="How detections reach AWS. Email is configured under Notifications above.">
            <Rows rows={[
              ["CloudWatch Logs", "every alert"],
              ["SNS", "HIGH and CRITICAL", "on anomaly open and on escalation"],
              ["Cooldown", `${d.incident.cooldown_minutes} min`, "after resolution, repeat notifications are suppressed"],
              ["Auto-resolve", `${d.incident.service_auto_resolve_windows} windows`, `service anomalies; HIPAA after ${d.incident.hipaa_auto_resolve_minutes} quiet minutes`],
              ["Mute", "per anomaly", "from any anomaly, pauses its AWS notifications"],
            ]} />
          </Section>
        </div>
      </div>
    </div>
  );
}
