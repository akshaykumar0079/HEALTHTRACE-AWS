import { useState } from "react";
import { Link } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ShieldWarning } from "@phosphor-icons/react";
import { api } from "@/lib/api";
import { Button, ErrorState, Skeleton, cx } from "./ui";
import { toast } from "@/app/toast";

/** The caller's role, so controls that cannot work are disabled with a reason instead of failing on click. */
export function useMe() {
  return useQuery({ queryKey: ["me"], queryFn: api.me, staleTime: 15_000, retry: false });
}

/**
 * Honest, persistent warnings about disabled security controls. Critical
 * warnings (authentication off) cannot be dismissed; the rest can be hidden for the session.
 */
export function SecurityBanner() {
  const { data } = useQuery({ queryKey: ["security-status"], queryFn: api.securityStatus, staleTime: 30_000, retry: false });
  const [hidden, setHidden] = useState(false);
  if (!data) return null;
  const critical = data.warnings.filter((w) => w.level === "critical");
  const others = data.warnings.filter((w) => w.level === "warning");
  if (critical.length === 0 && (hidden || others.length === 0)) return null;
  const shown = critical.length ? critical : others;
  return (
    <div role="alert" className={cx("border-b px-5 py-2.5 text-[12.5px]", critical.length ? "border-[rgb(240_90_115/0.35)] bg-[#f05a730d]" : "border-[var(--hairline)] bg-[#e3b35a0d]")}>
      <div className="flex items-start gap-3">
        <ShieldWarning size={17} className={cx("mt-0.5 shrink-0", critical.length ? "text-sev-critical" : "text-sev-medium")} />
        <ul className="min-w-0 flex-1 space-y-1">
          {shown.map((w) => <li key={w.code} className="text-fg-muted">{w.message}</li>)}
        </ul>
        <Link to="/app/settings#privacy" className="shrink-0 text-signal hover:underline">Security details</Link>
        {!critical.length && (
          <button type="button" onClick={() => setHidden(true)} className="shrink-0 text-fg-dim hover:text-fg">Dismiss</button>
        )}
      </div>
    </div>
  );
}

/** Settings > Privacy and security: what is on, what retention does, and what has not been verified. */
export function SecurityPrivacy() {
  const qc = useQueryClient();
  const me = useMe();
  const status = useQuery({ queryKey: ["security-status"], queryFn: api.securityStatus });
  const preview = useQuery({ queryKey: ["retention-preview"], queryFn: api.retentionPreview, retry: false });
  const run = useMutation({
    mutationFn: api.runRetention,
    onSuccess: (r) => {
      if (r.error) toast.error("Cleanup failed", r.error);
      else toast.success("Cleanup finished", `Deleted ${Object.values(r.deleted).reduce((a, b) => a + b, 0)} rows.`);
      void qc.invalidateQueries({ queryKey: ["retention-preview"] });
    },
    onError: (e) => toast.error("Cleanup not run", e instanceof Error ? e.message : "Unexpected error"),
  });
  if (status.isLoading) return <Skeleton className="h-40" />;
  if (status.error || !status.data) return <ErrorState error={status.error} onRetry={() => status.refetch()} />;
  const s = status.data;
  const admin = me.data?.can.admin ?? false;
  return (
    <div className="space-y-6">
      <ul className="space-y-2" aria-label="Security warnings">
        {s.warnings.map((w) => (
          <li key={w.code} className="text-[12.5px] leading-relaxed">
            <span className={cx("mr-2 font-medium", w.level === "critical" ? "text-sev-critical" : w.level === "warning" ? "text-sev-medium" : "text-fg-dim")}>
              {w.level === "critical" ? "Critical" : w.level === "warning" ? "Warning" : "Note"}
            </span>
            <span className="text-fg-muted">{w.message}</span>
          </li>
        ))}
      </ul>

      <div>
        <h3 className="text-[13px] font-medium text-fg">Roles</h3>
        <dl className="mt-2 divide-y divide-[var(--hairline)] text-[12.5px]">
          {Object.entries(s.roles).map(([role, can]) => (
            <div key={role} className="grid gap-1 py-2 sm:grid-cols-[110px_1fr]">
              <dt className="font-medium text-fg">{role}{me.data?.role === role ? " (you)" : ""}</dt>
              <dd className="text-fg-muted">{can.join("; ")}</dd>
            </div>
          ))}
        </dl>
      </div>

      <div>
        <h3 className="text-[13px] font-medium text-fg">Retention</h3>
        <div className="mt-2 overflow-x-auto">
          <table className="w-full min-w-[520px] text-left text-[12.5px]">
            <caption className="sr-only">Retention policy</caption>
            <thead className="text-[11.5px] text-fg-dim"><tr><th scope="col" className="py-1.5 font-normal">Data</th><th scope="col" className="py-1.5 font-normal">Kept</th><th scope="col" className="py-1.5 font-normal">Would delete now</th><th scope="col" className="py-1.5 font-normal">Rule</th></tr></thead>
            <tbody className="divide-y divide-[var(--hairline)]">
              {s.retention.policy.map((p) => (
                <tr key={p.data}>
                  <td className="py-2 text-fg">{p.data}</td>
                  <td className="py-2 font-mono text-fg-muted">{p.keep}</td>
                  <td className="py-2 font-mono text-fg-muted">{preview.data ? preview.data.would_delete[RETENTION_KEY[p.data] ?? ""] ?? 0 : "-"}</td>
                  <td className="py-2 text-fg-dim">{p.rule}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-3">
          <Button size="sm" variant="danger" busy={run.isPending} disabled={!admin} onClick={() => run.mutate()}>Run cleanup now</Button>
          {!admin && <span className="text-[12px] text-fg-dim">Needs the admin role.</span>}
          {preview.isError && <span className="text-[12px] text-fg-dim">Preview unavailable.</span>}
        </div>
      </div>

      <div>
        <h3 className="text-[13px] font-medium text-fg">Processing</h3>
        <p className="mt-1 text-[12.5px] leading-relaxed text-fg-muted">
          Redaction is {s.redaction.enabled ? "on" : "OFF"}. Data source: {s.processing.data_source}. Database: {s.processing.database}.
          Cloud integrations: AWS {s.processing.cloud_integrations.aws_mode}, email {s.processing.cloud_integrations.email_enabled ? "enabled" : "disabled"}. Everything is processed locally unless those are turned on.
        </p>
      </div>

      <div>
        <h3 className="text-[13px] font-medium text-fg">Not verified</h3>
        <ul className="mt-1 list-disc space-y-1 pl-5 text-[12.5px] leading-relaxed text-fg-muted">
          {s.not_verified.map((n) => <li key={n}>{n}</li>)}
        </ul>
      </div>
    </div>
  );
}

const RETENTION_KEY: Record<string, string> = {
  "Window metrics": "metrics",
  "Evidence records": "evidence",
  "Alerts": "alerts",
  "Resolved incidents": "resolved_incidents",
  "Notification attempts": "notification_attempts",
  "Simulation runs": "simulation_runs",
  "Audit log": "audit",
};
