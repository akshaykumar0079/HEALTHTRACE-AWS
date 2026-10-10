import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router";
import { api } from "@/lib/api";
import type { AwsIntegrationLabel } from "@/lib/types";
import { Skeleton, cx } from "./ui";

const TONE: Record<AwsIntegrationLabel, string> = {
  MOCK: "text-sev-medium bg-[#e3b35a14] shadow-[inset_0_0_0_1px_rgb(227_179_90/0.35)]",
  "NOT CONFIGURED": "text-fg-muted bg-ink-800 shadow-[inset_0_0_0_1px_var(--hairline-strong)]",
  CONFIGURED: "text-signal bg-[#56dcc812] shadow-[inset_0_0_0_1px_rgb(86_220_200/0.3)]",
  ERROR: "text-sev-critical bg-[#f05a7312] shadow-[inset_0_0_0_1px_rgb(240_90_115/0.35)]",
};

export function AwsStatusBadge({ label }: { label: AwsIntegrationLabel }) {
  return <span className={cx("inline-flex items-center rounded-full px-2.5 py-1 font-mono text-[11px] font-medium tracking-wide", TONE[label])}>{label}</span>;
}

/** Honest AWS state: off by default, mock is labelled as mock, "configured" is not "verified". */
export function AwsIntegration() {
  const { data, isLoading } = useQuery({ queryKey: ["aws-status"], queryFn: api.awsStatus, staleTime: 15_000 });
  if (isLoading) return <Skeleton className="mb-3 h-16" />;
  if (!data) return null;
  const i = data.integration;
  return (
    <div className="mb-3 rounded-[12px] bg-ink-850 p-4 shadow-[inset_0_0_0_1px_var(--hairline)]">
      <div className="flex flex-wrap items-center gap-3">
        <span className="text-[13px] font-medium text-fg">AWS CloudWatch Logs and SNS</span>
        <AwsStatusBadge label={i.status} />
        {i.status === "CONFIGURED" && <span className="text-[12px] text-fg-dim">{i.verified ? "verified by a successful call this session" : "not yet verified"}</span>}
      </div>
      <p className="mt-2 text-[12.5px] leading-relaxed text-fg-muted">{i.detail}</p>
      <p className="mt-1.5 text-[12px] leading-relaxed text-fg-dim">{data.requirement_note}</p>
      <Link to="/app/aws" className="mt-2 inline-block text-[12.5px] font-medium text-fg-muted hover:text-signal">Open AWS integration details</Link>
    </div>
  );
}
