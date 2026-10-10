import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle, EnvelopeSimple, PaperPlaneTilt, WarningOctagon } from "@phosphor-icons/react";
import { ApiError, api } from "@/lib/api";
import type { NotificationAttempt, NotificationSettingsInput, NotificationSettingsView } from "@/lib/types";
import { ago, stamp } from "@/lib/format";
import { Button, ErrorState, Field, Skeleton, cx, inputClass } from "./ui";
import { ConfirmDialog } from "./Confirm";
import { toast } from "@/app/toast";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function parseRecipients(text: string): { list: string[]; error: string | null } {
  const list = text.split(/[,\n;]/).map((s) => s.trim()).filter(Boolean);
  if (list.length === 0) return { list, error: "Enter at least one recipient email address." };
  if (list.length > 5) return { list, error: "At most 5 recipients are allowed." };
  const bad = list.find((r) => !EMAIL_RE.test(r) || r.length > 254);
  return { list, error: bad ? `"${bad.slice(0, 40)}" is not a valid email address.` : null };
}

function formatCooldown(seconds: number): string {
  if (seconds === 0) return "off";
  if (seconds % 3600 === 0) return `${seconds / 3600} h`;
  if (seconds % 60 === 0) return `${seconds / 60} min`;
  return `${seconds} s`;
}

const ATTEMPT_LABEL: Record<NotificationAttempt["status"], { text: string; tone: string }> = {
  accepted: { text: "Accepted by provider", tone: "text-signal" },
  failed: { text: "Failed", tone: "text-sev-critical" },
  skipped: { text: "Skipped", tone: "text-fg-dim" },
};

function Attempts({ attempts }: { attempts: NotificationAttempt[] }) {
  if (!attempts.length) return <p className="text-[12.5px] text-fg-dim">No email attempts yet. Send a test email to check the provider.</p>;
  return (
    <ul className="divide-y divide-[var(--hairline)] rounded-[12px] bg-ink-850 shadow-[inset_0_0_0_1px_var(--hairline)]">
      {attempts.map((a) => (
        <li key={a.id} className="grid gap-1 px-4 py-2.5 text-[12.5px] sm:grid-cols-[110px_150px_1fr] sm:items-baseline sm:gap-3">
          <span className="font-mono text-[11.5px] text-fg-dim" title={stamp(a.ts)}>{ago(a.ts)}</span>
          <span className={cx("font-medium", ATTEMPT_LABEL[a.status].tone)}>{ATTEMPT_LABEL[a.status].text}</span>
          <span className="min-w-0 truncate text-fg-muted" title={a.detail ?? undefined}>
            {a.kind === "test" ? "Test email" : `Incident #${a.incident_id ?? "?"}${a.severity ? ` (${a.severity})` : ""}`}
            {a.detail ? ` · ${a.detail}` : ""}
          </span>
        </li>
      ))}
    </ul>
  );
}

function Form({ view }: { view: NotificationSettingsView }) {
  const qc = useQueryClient();
  const s = view.settings;
  const [enabled, setEnabled] = useState(s.enabled);
  const [recipients, setRecipients] = useState(s.recipients.join(", "));
  const [minSeverity, setMinSeverity] = useState<"HIGH" | "CRITICAL">(s.min_severity);
  const [cooldown, setCooldown] = useState(String(s.cooldown_seconds));
  const [confirmOff, setConfirmOff] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; text: string } | null>(null);

  const parsed = parseRecipients(recipients);
  const cooldownNum = Number(cooldown);
  const cooldownError = !/^\d+$/.test(cooldown.trim()) || cooldownNum > 86400 ? "Enter whole seconds from 0 to 86400." : null;
  const invalid = !!parsed.error || !!cooldownError;
  const body: NotificationSettingsInput = { enabled, recipients: parsed.list, min_severity: minSeverity, cooldown_seconds: cooldownNum };
  const dirty = enabled !== s.enabled || minSeverity !== s.min_severity || cooldownNum !== s.cooldown_seconds || parsed.list.join(",") !== s.recipients.join(",");

  const save = useMutation({
    mutationFn: () => api.saveNotificationSettings(body),
    onSuccess: (v) => {
      qc.setQueryData(["notification-settings"], v);
      toast.success("Notification settings saved", v.warnings?.[0]);
      setConfirmOff(false);
    },
    onError: (e) => {
      setConfirmOff(false);
      const forbidden = e instanceof ApiError && (e.status === 401 || e.status === 403);
      toast.error("Could not save", forbidden ? "Operator access is required. Add the operator token under API access." : e instanceof Error ? e.message : undefined);
    },
  });

  const test = useMutation({
    mutationFn: api.sendTestEmail,
    onSuccess: (r) => {
      void qc.invalidateQueries({ queryKey: ["notification-settings"] });
      setTestResult(
        r.ok
          ? { ok: true, text: `Accepted by ${r.provider}${r.provider_message_id ? ` (id ${r.provider_message_id})` : ""}. ${r.note ?? ""}` }
          : { ok: false, text: `Not sent: ${r.error ?? "the provider rejected the request"}` },
      );
    },
    onError: (e) => setTestResult({ ok: false, text: e instanceof Error ? e.message : "The test could not be started." }),
  });

  const submit = () => {
    if (invalid) return;
    // Turning alerts off is the one change that silences a safety channel: confirm it.
    if (s.enabled && !enabled) setConfirmOff(true);
    else save.mutate();
  };

  const last = view.attempts[0];
  const p = view.provider;
  return (
    <div className="space-y-6">
      <div className="grid gap-x-8 gap-y-3 rounded-[12px] bg-ink-850 p-4 text-[12.5px] shadow-[inset_0_0_0_1px_var(--hairline)] sm:grid-cols-3">
        <div>
          <p className="text-fg-dim">Provider</p>
          <p className="mt-1 font-medium text-fg">{p.name === "brevo" ? "Brevo (HTTPS API)" : "SMTP"}</p>
          <p className={cx("mt-0.5", p.configured ? "text-signal" : "text-sev-medium")}>
            {p.configured ? "Configured" : `Not configured: ${p.missing.join(", ") || "settings missing"}`}
          </p>
        </div>
        <div>
          <p className="text-fg-dim">Last attempt</p>
          {last ? (
            <>
              <p className={cx("mt-1 font-medium", ATTEMPT_LABEL[last.status].tone)}>{ATTEMPT_LABEL[last.status].text}</p>
              <p className="mt-0.5 text-fg-dim" title={stamp(last.ts)}>{ago(last.ts)} · {last.kind === "test" ? "test email" : `incident #${last.incident_id}`}</p>
            </>
          ) : (
            <p className="mt-1 text-fg-dim">None yet</p>
          )}
        </div>
        <div>
          <p className="text-fg-dim">This hour</p>
          <p className="mt-1 font-mono text-fg">{view.status.sent_last_hour} / {view.status.max_per_hour}</p>
          <p className="mt-0.5 text-fg-dim">flood guard limit</p>
        </div>
      </div>

      <form
        noValidate
        className="max-w-2xl space-y-5"
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        <label className="flex cursor-pointer items-start gap-3">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} className="mt-1 size-4 accent-[var(--color-signal)]" />
          <span>
            <span className="block text-[13.5px] font-medium text-fg">Send email alerts</span>
            <span className="block text-[12.5px] leading-relaxed text-fg-dim">
              Email the recipients when an incident opens or escalates to the minimum severity or above. Detection, the dashboard and AWS are unaffected either way.
            </span>
          </span>
        </label>

        <Field
          label="Recipients"
          htmlFor="notif-recipients"
          hint="Up to 5 addresses, separated by commas. Alerts contain incident details but no patient names."
        >
          <input
            id="notif-recipients"
            type="text"
            inputMode="email"
            autoComplete="off"
            value={recipients}
            onChange={(e) => setRecipients(e.target.value)}
            aria-invalid={!!parsed.error}
            aria-describedby={parsed.error ? "notif-recipients-error" : undefined}
            className={cx(inputClass, parsed.error && "shadow-[inset_0_0_0_1px_var(--color-sev-critical)]")}
          />
          {parsed.error && <p id="notif-recipients-error" role="alert" className="mt-1.5 text-[12px] text-sev-critical">{parsed.error}</p>}
        </Field>

        <div className="grid gap-5 sm:grid-cols-2">
          <Field label="Minimum severity" htmlFor="notif-min" hint="High emails High and Critical. Critical emails only Critical.">
            <select id="notif-min" value={minSeverity} onChange={(e) => setMinSeverity(e.target.value as "HIGH" | "CRITICAL")} className={inputClass}>
              {view.allowed_min_severities.map((sev) => (
                <option key={sev} value={sev}>{sev === "HIGH" ? "High and above" : "Critical only"}</option>
              ))}
            </select>
          </Field>
          <Field label="Cooldown (seconds)" htmlFor="notif-cooldown" hint={`At most one email per incident every ${formatCooldown(cooldownNum || 0)}. Escalations still send.`}>
            <input
              id="notif-cooldown"
              type="text"
              inputMode="numeric"
              value={cooldown}
              onChange={(e) => setCooldown(e.target.value)}
              aria-invalid={!!cooldownError}
              className={cx(inputClass, cooldownError && "shadow-[inset_0_0_0_1px_var(--color-sev-critical)]")}
            />
            {cooldownError && <p role="alert" className="mt-1.5 text-[12px] text-sev-critical">{cooldownError}</p>}
          </Field>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <Button type="submit" variant="primary" busy={save.isPending} disabled={invalid || !dirty}>
            Save settings
          </Button>
          <Button
            type="button"
            variant="secondary"
            busy={test.isPending}
            disabled={!p.configured || dirty}
            onClick={() => { setTestResult(null); test.mutate(); }}
            icon={<PaperPlaneTilt size={14} />}
            title={!p.configured ? "Configure the email provider first" : dirty ? "Save your changes first; the test uses the saved recipients" : "Send one test email to the saved recipients"}
          >
            Send test email
          </Button>
          {s.updated_at && <span className="text-[12px] text-fg-dim">Saved {ago(s.updated_at)}{s.updated_by ? ` by ${s.updated_by}` : ""}</span>}
        </div>

        {testResult && (
          <p role="status" className={cx("flex items-start gap-2 rounded-[12px] px-4 py-3 text-[12.5px] leading-relaxed shadow-[inset_0_0_0_1px_var(--hairline)]", testResult.ok ? "bg-ink-850 text-fg-muted" : "bg-[#f05a730d] text-sev-critical")}>
            {testResult.ok ? <CheckCircle size={16} weight="fill" className="mt-0.5 shrink-0 text-signal" /> : <WarningOctagon size={16} className="mt-0.5 shrink-0" />}
            <span>{testResult.text}</span>
          </p>
        )}
      </form>

      <div className="max-w-2xl space-y-2.5">
        <h3 className="flex items-center gap-2 text-[13px] font-medium text-fg"><EnvelopeSimple size={15} /> Recent email attempts</h3>
        <Attempts attempts={view.attempts} />
        <p className="text-[12px] leading-relaxed text-fg-dim">{view.status.delivery_note}</p>
        {view.status.config_warnings.map((w) => (
          <p key={w} className="text-[12px] text-sev-medium">{w}</p>
        ))}
        <p className="text-[12px] leading-relaxed text-fg-dim">
          The email API key is read from the server environment ({p.name === "brevo" ? "BREVO_API_KEY" : "SMTP_PASSWORD"}) and is never shown, stored in the database or returned by the API.
        </p>
      </div>

      <ConfirmDialog
        open={confirmOff}
        onOpenChange={setConfirmOff}
        title="Turn off email alerts?"
        body="High and Critical incidents will no longer be emailed. They still appear on the dashboard and, when enabled, in AWS."
        confirmLabel="Turn off and save"
        tone="danger"
        busy={save.isPending}
        onConfirm={() => save.mutate()}
      />
    </div>
  );
}

export function NotificationSettings() {
  const { data, isLoading, error, refetch } = useQuery({ queryKey: ["notification-settings"], queryFn: api.notificationSettings });
  if (isLoading) return <Skeleton className="h-72" />;
  if (error || !data) return <ErrorState error={error} onRetry={() => refetch()} />;
  // Re-mount the form when the saved values change so its fields start from what the server holds.
  return <Form key={data.settings.updated_at ?? "initial"} view={data} />;
}
