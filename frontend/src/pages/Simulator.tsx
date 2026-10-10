import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Flask, Play, ShieldCheck } from "@phosphor-icons/react";
import { api } from "@/lib/api";
import type { BenchmarkResult, SimResult } from "@/lib/types";
import { SEVERITY_HEX, KIND_LABEL, stamp } from "@/lib/format";
import { benchmarkLines, checkLabel, formatDelay, formatRate, verdict } from "@/lib/simulation";
import { Button, EmptyState, ErrorState, PageHeader, Panel, PanelHeader, SeverityBadge, SkeletonRows, Stat, cx } from "@/components/ui";
import { SimulatedBadge } from "@/components/StatusStrip";
import { useMe } from "@/components/Security";
import { toast } from "@/app/toast";

const TONE = { pass: "text-signal", fail: "text-sev-critical", limit: "text-sev-medium" } as const;
const LABEL_TEXT = { expected: "Expected", related: "Related side effect", false_positive: "False positive" } as const;

function Result({ result }: { result: SimResult }) {
  const v = verdict(result);
  const m = result.metrics;
  return (
    <Panel>
      <PanelHeader
        title={result.title}
        description={`Seed ${result.seed}. Synthetic data only. ${result.expected_alerts}`}
        actions={<span className={cx("text-[13px] font-medium", TONE[v.tone])} role="status">{v.label}</span>}
      />
      <div className="grid grid-cols-2 gap-5 border-t border-[var(--hairline)] p-5 sm:grid-cols-4">
        <Stat label="Detection delay">{formatDelay(m.detection_delay_s)}</Stat>
        <Stat label="False positives" sub={formatRate(m.false_positives_per_hour)}>{m.false_positive_incidents}</Stat>
        <Stat label="Time to resolve">{m.time_to_resolve_s == null ? "n/a" : formatDelay(m.time_to_resolve_s)}</Stat>
        <Stat label="HIGH/CRITICAL notifications" sub="decisions only; nothing is sent">{m.staff_notifications}</Stat>
      </div>

      <div className="overflow-x-auto border-t border-[var(--hairline)]">
        <table className="w-full min-w-[520px] text-left text-[12.5px]">
          <caption className="sr-only">Checks for {result.title}</caption>
          <thead className="text-[11.5px] text-fg-dim"><tr className="border-b border-[var(--hairline)]"><th scope="col" className="px-5 py-2.5 font-normal">Check</th><th scope="col" className="px-3 py-2.5 font-normal">Expected</th><th scope="col" className="px-3 py-2.5 font-normal">Observed</th><th scope="col" className="px-5 py-2.5 font-normal">Result</th></tr></thead>
          <tbody className="divide-y divide-[var(--hairline)]">
            {result.checks.map((c) => (
              <tr key={c.name}>
                <td className="px-5 py-2.5 text-fg">{checkLabel(c.name)}</td>
                <td className="px-3 py-2.5 font-mono text-fg-muted">{String(c.expected)}</td>
                <td className="px-3 py-2.5 font-mono text-fg-muted">{String(c.observed)}</td>
                <td className={cx("px-5 py-2.5 font-medium", c.passed ? "text-signal" : "text-sev-critical")}>{c.passed ? "Pass" : "Fail"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="border-t border-[var(--hairline)] px-5 py-4">
        <h3 className="text-[13px] font-medium text-fg">Incidents raised ({result.incidents.length})</h3>
        {result.incidents.length === 0 ? (
          <p className="mt-1 text-[12.5px] text-fg-dim">None. In a control run this is the correct outcome.</p>
        ) : (
          <ul className="mt-2 space-y-1.5">
            {result.incidents.map((i) => (
              <li key={i.incident_id} className="flex flex-wrap items-center gap-2 text-[12.5px]">
                <SeverityBadge severity={i.peak_severity} size="sm" />
                <span className="text-fg">{KIND_LABEL[i.kind]}: {i.entity}</span>
                <span className="text-fg-dim">{LABEL_TEXT[i.label]}</span>
                <span className="text-fg-dim">{i.evidence_count} evidence · {i.state.toLowerCase()}</span>
                <span className="sr-only" style={{ color: SEVERITY_HEX[i.peak_severity] }}>{i.peak_severity}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
      <p className="border-t border-[var(--hairline)] px-5 py-3 text-[11.5px] leading-relaxed text-fg-dim">
        <ShieldCheck size={13} className="mr-1 inline text-signal" />
        Isolation: {result.isolation.database}; AWS {result.isolation.aws_mode}; email {result.isolation.email}; external calls {result.isolation.external_calls}.
      </p>
    </Panel>
  );
}

export default function Simulator() {
  const qc = useQueryClient();
  const me = useMe();
  const scenarios = useQuery({ queryKey: ["sim-scenarios"], queryFn: api.simScenarios, staleTime: 5 * 60_000 });
  const runs = useQuery({ queryKey: ["sim-runs"], queryFn: () => api.simRuns(15) });
  const [result, setResult] = useState<SimResult | null>(null);
  const [bench, setBench] = useState<BenchmarkResult | null>(null);
  const [running, setRunning] = useState<string | null>(null);

  const can = me.data?.can ?? { operate: false, admin: false };

  const run = useMutation({
    mutationFn: (id: string) => api.runSimulation(id),
    onMutate: (id) => setRunning(id),
    onSuccess: (r) => {
      setResult(r);
      void qc.invalidateQueries({ queryKey: ["sim-runs"] });
    },
    onError: (e) => toast.error("Simulation not run", e instanceof Error ? e.message : "Unexpected error"),
    onSettled: () => setRunning(null),
  });
  const benchmark = useMutation({
    mutationFn: () => api.runBenchmark([11, 22, 33]),
    onMutate: () => setRunning("benchmark"),
    onSuccess: (r) => {
      setBench(r);
      void qc.invalidateQueries({ queryKey: ["sim-runs"] });
    },
    onError: (e) => toast.error("Benchmark not run", e instanceof Error ? e.message : "Unexpected error"),
    onSettled: () => setRunning(null),
  });

  const open = async (id: number) => {
    try {
      const r = await api.simRun(id);
      if ("checks" in r.result) setResult({ ...(r.result as SimResult), id });
      else setBench(r.result as unknown as BenchmarkResult);
    } catch (e) {
      toast.error("Could not load that run", e instanceof Error ? e.message : undefined);
    }
  };

  const busy = running !== null;

  return (
    <div className="space-y-5">
      <PageHeader
        title="Simulator"
        description="Replay safe, synthetic incidents through the real detection pipeline and check the alerts it raises. Runs use generated data in a temporary database: they never touch real systems, your incidents or any notification channel."
        actions={<SimulatedBadge />}
      />

      {!can.operate && me.data && (
        <p role="status" className="rounded-[12px] bg-ink-850 px-4 py-2.5 text-[12.5px] text-fg-muted shadow-[inset_0_0_0_1px_var(--hairline)]">
          Running simulations needs the operator role. You can view past results. Enter a token under Settings, API access.
        </p>
      )}

      <Panel>
        <PanelHeader title="Scenarios" description="Each scenario uses a fixed seed, so repeated runs give identical results." />
        {scenarios.isLoading ? <SkeletonRows rows={5} /> : scenarios.error ? (
          <ErrorState error={scenarios.error} onRetry={() => scenarios.refetch()} />
        ) : (
          <ul className="grid gap-px border-t border-[var(--hairline)] bg-[var(--hairline)] md:grid-cols-2">
            {scenarios.data?.scenarios.map((s) => (
              <li key={s.id} className="flex flex-col gap-2 bg-ink-900 p-5">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <h3 className="text-[13.5px] font-medium text-fg">{s.title}</h3>
                    <p className="mt-0.5 text-[12.5px] text-fg-dim">{s.description}</p>
                  </div>
                  <Button size="sm" icon={<Play size={13} />} busy={running === s.id} disabled={!can.operate || busy} onClick={() => run.mutate(s.id)} aria-label={`Run ${s.title}`}>
                    Run
                  </Button>
                </div>
                <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-[12px]">
                  <dt className="text-fg-dim">Expected</dt><dd className="text-fg-muted">{s.expected_alerts}</dd>
                  {s.expected_severity.length > 0 && (<><dt className="text-fg-dim">Severity</dt><dd className="text-fg-muted">{s.expected_severity.join(" or ")}</dd></>)}
                  {s.max_detection_delay_s != null && (<><dt className="text-fg-dim">Within</dt><dd className="text-fg-muted">{formatDelay(s.max_detection_delay_s)} of injection</dd></>)}
                  <dt className="text-fg-dim">Seed</dt><dd className="font-mono text-fg-muted">{s.seed}</dd>
                  {s.known_limit && (<><dt className="text-fg-dim">Note</dt><dd className="text-sev-medium">Known limit: this scenario is not reliably detected.</dd></>)}
                </dl>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      {running && running !== "benchmark" && (
        <p role="status" aria-live="polite" className="flex items-center gap-2 text-[12.5px] text-fg-muted"><Flask size={15} className="animate-pulse text-signal" /> Running the simulation. This takes a few seconds.</p>
      )}
      {result && <Result result={result} />}

      <Panel>
        <PanelHeader
          title="Benchmark"
          description="Runs every scenario on three seeds, including a normal-traffic control, and reports detection delay and false-positive rate. Takes about a minute."
          actions={<Button size="sm" busy={running === "benchmark"} disabled={!can.admin || busy} onClick={() => benchmark.mutate()}>Run benchmark</Button>}
        />
        {!can.admin && me.data && <p className="px-5 pb-3 text-[12px] text-fg-dim">Needs the admin role.</p>}
        {bench && (
          <div className="border-t border-[var(--hairline)] p-5">
            <ul className="space-y-1 text-[12.5px] text-fg-muted">{benchmarkLines(bench.summary).map((l) => <li key={l}>{l}</li>)}</ul>
            <p className="mt-2 text-[11.5px] text-fg-dim">Seeds {bench.seeds.join(", ")}. {bench.summary.passed} of {bench.summary.runs} runs met every expectation. Synthetic data: these figures describe this generator, not real traffic.</p>
          </div>
        )}
      </Panel>

      <Panel>
        <PanelHeader title="Previous runs" description="Stored with their full results." />
        {runs.isLoading ? <SkeletonRows rows={3} /> : runs.error ? (
          <ErrorState error={runs.error} onRetry={() => runs.refetch()} />
        ) : !runs.data?.items.length ? (
          <EmptyState title="No simulation runs yet" body="Run a scenario above. Results are kept for the configured retention period." className="py-10" />
        ) : (
          <ul className="divide-y divide-[var(--hairline)] border-t border-[var(--hairline)]">
            {runs.data.items.map((r) => (
              <li key={r.id}>
                <button type="button" onClick={() => open(r.id)} className="flex w-full items-center gap-3 px-5 py-2.5 text-left text-[12.5px] hover:bg-ink-800/60">
                  <span className={cx("w-14 shrink-0 font-medium", r.passed ? "text-signal" : "text-sev-critical")}>{r.passed ? "Passed" : "Failed"}</span>
                  <span className="min-w-0 flex-1 truncate text-fg">{r.scenario_id === "benchmark" ? "Benchmark" : r.summary.replace(/^(PASS|FAIL)[^:]*: /, "")}</span>
                  <span className="shrink-0 font-mono text-fg-dim">seed {r.seed}</span>
                  <span className="hidden shrink-0 text-fg-dim sm:inline">{stamp(r.created_at)}</span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </div>
  );
}
