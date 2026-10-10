import { useMutation, useQuery } from "@tanstack/react-query";
import { BellRinging, CheckCircle, Cloud, EnvelopeSimple, Key, PaperPlaneTilt, Plugs, WarningOctagon } from "@phosphor-icons/react";
import { api } from "@/lib/api";
import type { AwsCheckResult, ChannelStatus, EmailStatus } from "@/lib/types";
import { SIGNAL_HEX, SEVERITY_HEX, ago, num } from "@/lib/format";
import { Beacon, Button, ErrorState, PageHeader, Panel, PanelHeader, Skeleton, cx } from "@/components/ui";
import { toast } from "@/app/toast";

const MODE_COPY = {
  off: { label: "Off", body: "No AWS calls are made. Detection and the dashboard run fully without credentials.", color: "#627085" },
  mock: { label: "Mock", body: "Notifications are written to data/aws_mock.log instead of AWS. Useful for demos and CI.", color: SEVERITY_HEX.MEDIUM },
  live: { label: "Live", body: "Alerts go to CloudWatch Logs and HIGH or CRITICAL anomalies publish to SNS.", color: SIGNAL_HEX },
};

const IAM_POLICY = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
      "Resource": "arn:aws:logs:<region>:<account>:log-group:<CLOUDWATCH_LOG_GROUP>:*"
    },
    {
      "Effect": "Allow",
      "Action": "logs:DescribeLogGroups",
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": ["sns:Publish", "sns:GetTopicAttributes"],
      "Resource": "<SNS_TOPIC_ARN>"
    }
  ]
}`;

function CheckLine({ name, result }: { name: string; result?: { ok: boolean; detail: string } }) {
  if (!result) return null;
  return (
    <p className="flex items-start gap-2 text-[12.5px]">
      {result.ok ? <CheckCircle size={15} weight="fill" className="mt-0.5 shrink-0 text-signal" /> : <WarningOctagon size={15} className="mt-0.5 shrink-0 text-sev-critical" />}
      <span><span className="text-fg">{name}</span> <span className="text-fg-muted">{result.detail}</span></span>
    </p>
  );
}

function Channel({ icon, title, target, s, configured }: { icon: React.ReactNode; title: string; target: string; s: ChannelStatus; configured: boolean }) {
  const healthy = configured && (s.failed === 0 || (s.last_success_at && (!s.last_failure_at || s.last_success_at > s.last_failure_at)));
  return (
    <Panel>
      <PanelHeader
        title={<span className="flex items-center gap-2">{icon}{title}</span>}
        description={<span className="break-all font-mono">{target}</span>}
        actions={<Beacon color={!configured ? "#627085" : healthy ? SIGNAL_HEX : SEVERITY_HEX.CRITICAL} pulse={false} />}
      />
      <dl className="grid grid-cols-4 gap-4 border-y border-[var(--hairline)] px-5 py-4">
        {([["Sent", s.sent], ["Failed", s.failed], ["Skipped", s.skipped], ["Retries", s.retries]] as const).map(([k, v]) => (
          <div key={k}>
            <dt className="text-[11.5px] text-fg-dim">{k}</dt>
            <dd className={cx("mt-1 font-mono text-[18px]", k === "Failed" && v > 0 ? "text-sev-critical" : "text-fg")}>{num(v)}</dd>
          </div>
        ))}
      </dl>
      <dl className="space-y-2 px-5 py-4 text-[12.5px]">
        <div className="flex justify-between gap-4"><dt className="text-fg-dim">Last success</dt><dd className="text-fg-muted">{s.last_success_at ? ago(s.last_success_at) : "never"}</dd></div>
        <div className="flex justify-between gap-4"><dt className="text-fg-dim">Last failure</dt><dd className="text-fg-muted">{s.last_failure_at ? ago(s.last_failure_at) : "never"}</dd></div>
        {s.last_error && <p className="rounded-[10px] bg-[#f05a730f] px-3 py-2 font-mono text-[11.5px] leading-relaxed text-sev-critical">{s.last_error}</p>}
      </dl>
    </Panel>
  );
}

function EmailChannel({ e }: { e: EmailStatus }) {
  const rows: [string, React.ReactNode][] = [
    ["Email notification", e.enabled ? "Enabled" : "Disabled"],
    ["Email recipient", e.recipients.join(", ") || "(none)"],
    ["Email status", e.configured ? "Configured" : e.enabled ? `Not configured: ${e.missing.join(", ")} missing` : "Not configured"],
    ["Delivered by", e.provider === "brevo" ? "Brevo email API (HTTPS)" : `SMTP ${e.host}:${e.port}${e.use_tls ? " (STARTTLS)" : e.port === 465 ? " (SSL)" : ""}`],
    ["Sender", e.sender ?? (e.provider === "brevo" ? "(ALERT_EMAIL_FROM)" : "(SMTP_USERNAME)")],
    ["Sends for", `${e.severities.join(" and ")} incidents, once when opened and once per escalation`],
  ];
  return (
    <div className="grid gap-5 lg:grid-cols-2">
      <Channel icon={<EnvelopeSimple size={16} />} title={e.provider === "brevo" ? "Email (Brevo)" : "Email (SMTP)"} target={e.recipients.join(", ") || "ALERT_EMAIL_TO not set"} s={e} configured={e.enabled && e.configured} />
      <Panel>
        <PanelHeader title="Email settings" description="Set in the backend's local .env (run scripts/setup_email.py). API keys and passwords are never sent to the browser. AWS is not needed for email." />
        <dl className="divide-y divide-[var(--hairline)] border-t border-[var(--hairline)] text-[12.5px]">
          {rows.map(([k, v]) => (
            <div key={k} className="grid gap-1 px-5 py-3 sm:grid-cols-[170px_1fr]">
              <dt className="text-fg-dim">{k}</dt>
              <dd className="break-all font-mono text-fg">{v}</dd>
            </div>
          ))}
        </dl>
        {e.config_warnings.length > 0 && (
          <div className="space-y-1.5 border-t border-[var(--hairline)] px-5 py-4">
            {e.config_warnings.map((w) => <CheckLine key={w} name="Config" result={{ ok: false, detail: w }} />)}
          </div>
        )}
      </Panel>
    </div>
  );
}

export default function Aws() {
  const status = useQuery({ queryKey: ["aws-status"], queryFn: api.awsStatus, refetchInterval: 5000 });
  const email = useQuery({ queryKey: ["email-status"], queryFn: api.emailStatus, refetchInterval: 5000 });
  const onDone = (label: string) => (r: AwsCheckResult) => {
    const ok = r.cloudwatch.ok && r.sns.ok;
    (ok ? toast.success : toast.error)(`${label}: ${ok ? "all channels OK" : "check the results"}`, `CloudWatch: ${r.cloudwatch.detail}. SNS: ${r.sns.detail}.`);
    void status.refetch();
  };
  const onFail = (label: string) => (e: unknown) => toast.error(`${label} failed`, e instanceof Error ? e.message : undefined);
  const test = useMutation({ mutationFn: api.awsTestConnection, onSuccess: onDone("Connection test"), onError: onFail("Connection test") });
  const send = useMutation({ mutationFn: api.awsTestAlert, onSuccess: onDone("Test alert"), onError: onFail("Test alert") });

  if (status.isLoading) return <div className="space-y-5"><Skeleton className="h-40" /><Skeleton className="h-64" /></div>;
  if (status.error || !status.data) return <ErrorState error={status.error} onRetry={() => status.refetch()} />;
  const d = status.data;
  const mode = MODE_COPY[d.mode];
  const lastCheck = test.data ?? send.data;

  return (
    <div className="space-y-5">
      <PageHeader
        title="Notifications"
        description="HIGH and CRITICAL incidents are emailed directly over SMTP (no AWS needed). Optionally, alerts are also shipped to CloudWatch Logs and paged through SNS; the backend never holds AWS keys."
        actions={
          <>
            <Button icon={<Plugs size={15} />} busy={test.isPending} onClick={() => test.mutate()}>Test connection</Button>
            <Button variant="primary" icon={<PaperPlaneTilt size={15} />} busy={send.isPending} onClick={() => send.mutate()} disabled={d.mode === "off"}>
              Send test alert
            </Button>
          </>
        }
      />

      {email.data && <EmailChannel e={email.data} />}

      <Panel>
        <div className="grid divide-[var(--hairline)] md:grid-cols-4 md:divide-x">
          <div className="p-5">
            <p className="text-[12px] text-fg-dim">Mode</p>
            <p className="mt-2 flex items-center gap-2 text-[20px] font-semibold tracking-tight" style={{ color: mode.color }}>
              <Beacon color={mode.color} pulse={d.mode === "live"} /> {mode.label}
            </p>
            <p className="mt-2 text-[12px] leading-relaxed text-fg-dim">{mode.body}</p>
          </div>
          <div className="p-5">
            <p className="text-[12px] text-fg-dim">Region</p>
            <p className="mt-2 font-mono text-[18px] text-fg">{d.region}</p>
          </div>
          <div className="p-5">
            <p className="text-[12px] text-fg-dim">Credentials</p>
            <p className="mt-2 flex items-center gap-2 font-mono text-[15px] text-fg"><Key size={15} /> {d.credentials_source ?? (d.mode === "live" ? "not found" : "not needed")}</p>
            <p className="mt-2 text-[12px] text-fg-dim">Resolved by the AWS SDK default chain. Keys are never shown or sent to the browser.</p>
          </div>
          <div className="p-5">
            <p className="text-[12px] text-fg-dim">Notifier queue</p>
            <p className="mt-2 font-mono text-[18px] text-fg">{d.queue_depth}</p>
            <p className="mt-2 text-[12px] text-fg-dim">Retries 5 times with exponential backoff and never blocks detection.</p>
          </div>
        </div>
        {(d.config_warnings?.length ?? 0) > 0 && (
          <div className="space-y-1.5 border-t border-[var(--hairline)] px-5 py-4">
            {d.config_warnings!.map((w) => (
              <CheckLine key={w} name="Config" result={{ ok: false, detail: w }} />
            ))}
          </div>
        )}
        {lastCheck && (
          <div className="space-y-1.5 border-t border-[var(--hairline)] px-5 py-4">
            <CheckLine name="CloudWatch" result={lastCheck.cloudwatch} />
            <CheckLine name="SNS" result={lastCheck.sns} />
          </div>
        )}
      </Panel>

      <div className="grid gap-5 lg:grid-cols-2">
        <Channel icon={<Cloud size={16} />} title="CloudWatch Logs" target={d.cloudwatch.log_group} s={d.cloudwatch} configured={d.mode !== "off"} />
        <Channel icon={<BellRinging size={16} />} title="Amazon SNS" target={d.sns.topic_arn ?? "SNS_TOPIC_ARN not set"} s={d.sns} configured={d.mode !== "off" && (d.sns.configured || d.mode === "mock")} />
      </div>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        <Panel>
          <PanelHeader title="Configuration" description="Set as environment variables on the backend; in AWS through the ECS task definition and SSM Parameter Store." />
          <dl className="divide-y divide-[var(--hairline)] border-t border-[var(--hairline)] font-mono text-[12.5px]">
            {[
              ["AWS_MODE", d.mode, "off, mock or live"],
              ["AWS_REGION", d.region, "region for both clients"],
              ["CLOUDWATCH_LOG_GROUP", d.cloudwatch.log_group, "pre-create it, or grant logs:CreateLogGroup"],
              ["CLOUDWATCH_LOG_STREAM", d.cloudwatch.log_stream ?? "daily (YYYY-MM-DD)", "created on first alert"],
              ["SNS_TOPIC_ARN", d.sns.topic_arn ?? "(unset)", "HIGH and CRITICAL pages"],
            ].map(([k, v, hint]) => (
              <div key={k} className="grid gap-1 px-5 py-3 sm:grid-cols-[200px_1fr]">
                <dt className="text-fg-dim">{k}</dt>
                <dd className="break-all text-fg">{v} <span className="ml-2 font-sans text-[11.5px] text-fg-dim">{hint}</span></dd>
              </div>
            ))}
          </dl>
        </Panel>
        <Panel>
          <PanelHeader title="Least-privilege IAM policy" description="Attach to the ECS task role or your own IAM identity. Add logs:CreateLogGroup only if the app should create the group itself (docs/aws-iam.md)." />
          <pre className="mx-5 mb-5 overflow-x-auto rounded-[12px] bg-ink-950 p-4 font-mono text-[11.5px] leading-relaxed text-fg-muted shadow-[inset_0_0_0_1px_var(--hairline)]">
            {IAM_POLICY}
          </pre>
        </Panel>
      </div>
    </div>
  );
}
