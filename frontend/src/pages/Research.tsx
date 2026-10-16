import { useMemo, useRef, useState, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowsClockwise, CheckCircle, Flask, ShieldWarning, UploadSimple, WarningCircle } from "@phosphor-icons/react";
import { api } from "@/lib/api";
import {
  buildMapping, emptyDraft, formatBytes, num, pct, precheckFile, seconds, type MappingDraft,
} from "@/lib/research";
import type {
  ResearchExperiment, ResearchField, ResearchInfo, ResearchKind, ResearchMethodResult, ResearchReport, ResearchUploadResult,
} from "@/lib/types";
import { stamp } from "@/lib/format";
import { Button, EmptyState, ErrorState, Field, PageHeader, Panel, PanelHeader, Segmented, SkeletonRows, Stat, cx, inputClass } from "@/components/ui";
import { useMe } from "@/components/Security";
import { toast } from "@/app/toast";

const KIND_OPTIONS: { value: ResearchKind; label: string }[] = [
  { value: "app", label: "Service log" },
  { value: "audit", label: "Record access log" },
  { value: "auth", label: "Login log" },
];

const errMsg = (e: unknown) => (e instanceof Error ? e.message : "Unexpected error");

function Step({ n, title, children }: { n: number; title: string; children: ReactNode }) {
  return (
    <Panel>
      <PanelHeader title={<span><span className="mr-2 font-mono text-fg-dim">{n}.</span>{title}</span>} />
      <div className="border-t border-[var(--hairline)] p-5">{children}</div>
    </Panel>
  );
}

function PrivacyNotice({ info, ack, onAck }: { info: ResearchInfo; ack: boolean; onAck: (v: boolean) => void }) {
  return (
    <Panel>
      <div className="flex gap-3 p-5">
        <ShieldWarning size={22} className="mt-0.5 shrink-0 text-sev-medium" />
        <div className="space-y-3">
          <h2 className="text-[13.5px] font-medium text-fg">Before you upload</h2>
          <p className="text-[12.5px] leading-relaxed text-fg-muted">{info.warning}</p>
          <p className="text-[12px] text-fg-dim">
            Limits: {info.limits.max_upload_mb} MB, {info.limits.max_rows.toLocaleString()} rows, {info.limits.max_columns} columns. Formats: {info.formats.join(", ")}.
            Uploads and results are deleted after {info.retention_days || "an unlimited number of"} days.
          </p>
          <label className="flex items-start gap-2 text-[12.5px] text-fg">
            <input type="checkbox" className="mt-0.5" checked={ack} onChange={(e) => onAck(e.target.checked)} />
            I understand. This file is synthetic or properly de-identified.
          </label>
        </div>
      </div>
    </Panel>
  );
}

function MappingEditor({ info, upload, draft, setDraft }: {
  info: ResearchInfo; upload: ResearchUploadResult; draft: MappingDraft; setDraft: (d: MappingDraft) => void;
}) {
  const insp = upload.inspection;
  const cols = insp.columns.map((c) => c.name);
  const fields: ResearchField[] = info.kinds[draft.kind].fields;
  const set = (patch: Partial<MappingDraft>) => setDraft({ ...draft, ...patch });
  const mappedCols = new Set(Object.values(draft.columns).filter(Boolean));

  return (
    <div className="space-y-6">
      <Field label="What kind of log is this?" htmlFor="kind">
        <Segmented<ResearchKind> label="Dataset kind" value={draft.kind} options={KIND_OPTIONS}
          onChange={(kind) => setDraft(emptyDraft(kind, cols, info.kinds[kind].fields))} />
      </Field>

      <div className="grid gap-4 md:grid-cols-2">
        {fields.map((f) => {
          const id = `map-${f.name}`;
          const col = draft.columns[f.name] ?? "";
          return (
            <Field key={f.name} label={`${f.label}${f.required ? " *" : ""}`} htmlFor={id} hint={f.note}>
              <select id={id} className={inputClass} value={col}
                onChange={(e) => set({ columns: { ...draft.columns, [f.name]: e.target.value } })}>
                <option value="">— not mapped —</option>
                {cols.map((c) => <option key={c} value={c}>{c}</option>)}
              </select>
              {!col && f.can_default && f.values && (
                <select aria-label={`Constant for ${f.label}`} className={cx(inputClass, "mt-2")} value={draft.defaults[f.name] ?? ""}
                  onChange={(e) => set({ defaults: { ...draft.defaults, [f.name]: e.target.value } })}>
                  <option value="">{f.default ? `Default: ${f.default}` : "No constant"}</option>
                  {f.values.map((v) => <option key={v} value={v}>Use {v} for every row</option>)}
                </select>
              )}
              {!col && f.can_default && !f.values && (
                <input aria-label={`Constant for ${f.label}`} className={cx(inputClass, "mt-2")} placeholder={f.default ? `Default: ${f.default}` : "Constant (optional)"}
                  value={draft.defaults[f.name] ?? ""} onChange={(e) => set({ defaults: { ...draft.defaults, [f.name]: e.target.value } })} />
              )}
            </Field>
          );
        })}
      </div>

      <Field label="Timezone for timestamps without an offset" htmlFor="tz" hint="IANA name such as UTC or America/Chicago. Timestamps with an offset or Z are used as they are.">
        <input id="tz" className={inputClass} value={draft.timezone} onChange={(e) => set({ timezone: e.target.value })} />
      </Field>

      {fields.filter((f) => f.values && draft.columns[f.name] && insp.distinct_values[draft.columns[f.name]!]).map((f) => (
        <div key={f.name}>
          <h3 className="text-[13px] font-medium text-fg">Value mapping: {f.label}</h3>
          <p className="mb-2 text-[12px] text-fg-dim">Leave on "auto" where your value already matches ({f.values!.join(", ")}). Rows whose value cannot be interpreted are rejected, never guessed.</p>
          <ul className="grid gap-2 sm:grid-cols-2">
            {insp.distinct_values[draft.columns[f.name]!]!.map((v) => (
              <li key={v} className="flex items-center gap-2 text-[12.5px]">
                <span className="min-w-0 flex-1 truncate font-mono text-fg-muted" title={v}>{v}</span>
                <select aria-label={`Map ${v} for ${f.label}`} className={cx(inputClass, "h-8 w-40")}
                  value={draft.values[f.name]?.[v] ?? "auto"}
                  onChange={(e) => set({ values: { ...draft.values, [f.name]: { ...(draft.values[f.name] ?? {}), [v]: e.target.value } } })}>
                  <option value="auto">auto</option>
                  {f.values!.map((c) => <option key={c} value={c}>{c}</option>)}
                </select>
              </li>
            ))}
          </ul>
        </div>
      ))}

      <fieldset className="space-y-3 rounded-[12px] p-4 shadow-[inset_0_0_0_1px_var(--hairline)]">
        <legend className="px-1 text-[13px] font-medium text-fg">Ground-truth labels (optional)</legend>
        <label className="flex items-center gap-2 text-[12.5px] text-fg">
          <input type="checkbox" checked={draft.label.enabled} onChange={(e) => set({ label: { ...draft.label, enabled: e.target.checked } })} />
          My file has a column that says which rows are real anomalies
        </label>
        {!draft.label.enabled ? (
          <p className="text-[12px] text-fg-dim">Without labels the detector is run and its incidents are listed. Precision, recall and false-alarm rate are not computed.</p>
        ) : (
          <div className="grid gap-4 md:grid-cols-2">
            <Field label="Label column" htmlFor="label-col" hint="Must not be a column you mapped as detector input.">
              <select id="label-col" className={inputClass} value={draft.label.column}
                onChange={(e) => set({ label: { ...draft.label, column: e.target.value, positives: [] } })}>
                <option value="">— choose —</option>
                {cols.filter((c) => !mappedCols.has(c)).map((c) => <option key={c} value={c}>{c}</option>)}
              </select>
            </Field>
            <Field label="Values that mean 'anomaly'" htmlFor="label-pos" hint="Case-insensitive.">
              {draft.label.column && insp.distinct_values[draft.label.column] ? (
                <div id="label-pos" role="group" aria-label="Anomaly values" className="flex flex-wrap gap-3">
                  {insp.distinct_values[draft.label.column]!.map((v) => (
                    <label key={v} className="flex items-center gap-1.5 text-[12.5px]">
                      <input type="checkbox" checked={draft.label.positives.includes(v)}
                        onChange={(e) => set({ label: { ...draft.label, positives: e.target.checked ? [...draft.label.positives, v] : draft.label.positives.filter((x) => x !== v) } })} />
                      <span className="font-mono">{v}</span>
                    </label>
                  ))}
                </div>
              ) : (
                <input id="label-pos" className={inputClass} placeholder="comma-separated, e.g. 1, true"
                  value={draft.label.positives.join(", ")}
                  onChange={(e) => set({ label: { ...draft.label, positives: e.target.value.split(",").map((s) => s.trim()).filter(Boolean) } })} />
              )}
            </Field>
            <Field label="An anomaly belongs to" htmlFor="label-scope">
              <select id="label-scope" className={inputClass} value={draft.label.scope}
                onChange={(e) => set({ label: { ...draft.label, scope: e.target.value as "entity" | "dataset" } })}>
                <option value="entity">its service / user (match the entity)</option>
                <option value="dataset">the whole dataset (match any incident)</option>
              </select>
            </Field>
            <Field label="Merge labelled rows closer than (seconds)" htmlFor="label-gap">
              <input id="label-gap" type="number" min={0} max={3600} className={inputClass} value={draft.label.gap}
                onChange={(e) => set({ label: { ...draft.label, gap: Number(e.target.value) } })} />
            </Field>
            <p className="text-[12px] leading-relaxed text-fg-dim md:col-span-2">
              Labels are treated as complete: an incident outside every labelled interval counts as a false alarm.
            </p>
          </div>
        )}
      </fieldset>
    </div>
  );
}

function ReportView({ report }: { report: ResearchReport }) {
  return (
    <div className="space-y-4" aria-live="polite">
      <p role="status" className={cx("flex items-center gap-2 text-[13px] font-medium", report.ok ? "text-signal" : "text-sev-critical")}>
        {report.ok ? <CheckCircle size={16} /> : <WarningCircle size={16} />}
        {report.ok ? "Valid. You can run it." : "Not valid yet. Fix the problems below."}
      </p>
      {report.errors.length > 0 && (
        <ul className="space-y-1 text-[12.5px] text-sev-critical">{report.errors.map((e) => <li key={e.code + e.field}>{e.message}</li>)}</ul>
      )}
      {report.warnings.length > 0 && (
        <ul className="list-disc space-y-1 pl-5 text-[12.5px] text-sev-medium">{report.warnings.map((w) => <li key={w}>{w}</li>)}</ul>
      )}
      {report.rows && (
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          <Stat label="Rows read">{report.rows.total.toLocaleString()}</Stat>
          <Stat label="Accepted">{report.rows.accepted.toLocaleString()}</Stat>
          <Stat label="Rejected">{report.rows.rejected.toLocaleString()}</Stat>
          <Stat label="Time span">{report.time_span ? `${num(report.time_span.hours, 2)} h` : "n/a"}</Stat>
        </div>
      )}
      {report.rows && Object.keys(report.rows.rejects_by_code).length > 0 && (
        <table className="w-full text-left text-[12.5px]">
          <caption className="sr-only">Rejected rows by reason</caption>
          <thead className="text-[11.5px] text-fg-dim"><tr><th scope="col" className="py-1 font-normal">Reason</th><th scope="col" className="py-1 font-normal">Rows</th><th scope="col" className="py-1 font-normal">First rows (numbers only)</th></tr></thead>
          <tbody className="divide-y divide-[var(--hairline)]">
            {Object.entries(report.rows.rejects_by_code).map(([code, n]) => (
              <tr key={code}>
                <td className="py-1.5 pr-3"><span className="font-mono text-fg">{code}</span><span className="block text-fg-dim">{report.rows!.explanations[code]}</span></td>
                <td className="py-1.5 pr-3 font-mono">{n}</td>
                <td className="py-1.5 font-mono text-fg-dim">{(report.rows!.first_rows_by_code[code] ?? []).slice(0, 8).join(", ")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {report.unmapped_values && Object.keys(report.unmapped_values).length > 0 && (
        <div className="text-[12.5px] text-fg-muted">
          Values that could not be interpreted (add them under Value mapping):
          <ul className="mt-1 space-y-0.5">
            {Object.entries(report.unmapped_values).map(([f, vs]) => <li key={f}><span className="text-fg">{f}:</span> <span className="font-mono">{vs.join(", ")}</span></li>)}
          </ul>
        </div>
      )}
      {report.labels && (
        <p className="text-[12.5px] text-fg-muted">
          Labels: {report.labels.positive_rows.toLocaleString()} anomaly rows form {report.labels.intervals} interval(s).
        </p>
      )}
    </div>
  );
}

function MethodCard({ m, titles }: { m: ResearchMethodResult; titles: Record<string, string> }) {
  const title = titles[m.method] ?? m.method;
  if (!m.applicable) {
    return <li className="px-5 py-4 text-[12.5px] text-fg-dim"><span className="text-fg">{title}</span>: {m.reason}</li>;
  }
  const ev = m.evaluation!;
  return (
    <li className="space-y-3 px-5 py-4">
      <h3 className="text-[13px] font-medium text-fg">{title} <span className="font-normal text-fg-dim">· {m.incidents_found} incident(s)</span></h3>
      {ev.metrics_measured ? (
        <div>
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4 lg:grid-cols-6">
            <Stat label="Precision">{pct(ev.metrics.precision)}</Stat>
            <Stat label="Recall">{pct(ev.metrics.recall)}</Stat>
            <Stat label="False alarms / h" sub={`${ev.metrics.fp} false alarm(s)`}>{num(ev.metrics.false_alarms_per_hour)}</Stat>
            <Stat label="Detection delay" sub={`median of ${ev.metrics.delay_s.n}`}>{seconds(ev.metrics.delay_s.median)}</Stat>
            <Stat label="Hits / misses" sub={`${ev.metrics.intervals} labelled interval(s)`}>{ev.metrics.tp} / {ev.metrics.fn}</Stat>
            <Stat label="F1">{num(ev.metrics.f1)}</Stat>
          </div>
          <table className="mt-3 w-full text-left text-[12.5px]">
            <caption className="sr-only">Labelled intervals for {title}</caption>
            <thead className="text-[11.5px] text-fg-dim"><tr><th scope="col" className="py-1 font-normal">Entity</th><th scope="col" className="py-1 font-normal">Interval</th><th scope="col" className="py-1 font-normal">Result</th></tr></thead>
            <tbody className="divide-y divide-[var(--hairline)]">
              {ev.intervals.map((i) => (
                <tr key={i.entity + i.start}>
                  <td className="py-1.5 pr-3 font-mono">{i.entity}</td>
                  <td className="py-1.5 pr-3 text-fg-muted">{stamp(i.start)} to {stamp(i.end)}</td>
                  <td className={cx("py-1.5", i.detected ? "text-signal" : "text-sev-critical")}>
                    {i.detected ? `Detected after ${seconds(i.delay_s)}` : "Missed"}{i.starts_in_detector_warmup ? " (starts during detector warm-up)" : ""}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <ul className="mt-2 list-disc space-y-0.5 pl-5 text-[11.5px] text-fg-dim">{ev.assumptions.map((a) => <li key={a}>{a}</li>)}</ul>
        </div>
      ) : (
        <p role="note" className="rounded-[12px] bg-ink-850 px-4 py-3 text-[12.5px] leading-relaxed text-fg-muted shadow-[inset_0_0_0_1px_var(--hairline)]">
          <strong className="text-fg">Descriptive results only.</strong> {ev.note}
        </p>
      )}
      {m.incidents && m.incidents.length > 0 ? (
        <table className="w-full text-left text-[12.5px]">
          <caption className="sr-only">Incidents found by {title}</caption>
          <thead className="text-[11.5px] text-fg-dim"><tr><th scope="col" className="py-1 font-normal">First alert</th><th scope="col" className="py-1 font-normal">Kind</th><th scope="col" className="py-1 font-normal">Entity</th><th scope="col" className="py-1 font-normal">Severity</th></tr></thead>
          <tbody className="divide-y divide-[var(--hairline)]">
            {m.incidents.slice(0, 20).map((i) => (
              <tr key={i.kind + i.entity + i.first_alert_at}>
                <td className="py-1.5 pr-3 text-fg-muted">{stamp(i.first_alert_at)}</td>
                <td className="py-1.5 pr-3">{i.kind}</td>
                <td className="py-1.5 pr-3 font-mono">{i.entity}</td>
                <td className="py-1.5">{i.peak_severity ?? "n/a"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p className="text-[12.5px] text-fg-dim">No incidents were raised.</p>
      )}
      {m.incidents_truncated && <p className="text-[11.5px] text-fg-dim">Only the first 200 incidents are stored; the full list is not kept.</p>}
    </li>
  );
}

function ExperimentView({ exp, info, onRerun, rerunning }: { exp: ResearchExperiment; info?: ResearchInfo; onRerun: () => void; rerunning: boolean }) {
  const titles = Object.fromEntries((info?.methods ?? []).map((m) => [m.id, m.title]));
  const d = exp.result.dataset;
  return (
    <Panel>
      <PanelHeader
        title={`Experiment ${exp.id}`}
        description={`${exp.upload.filename} · ${exp.config.mode === "labeled" ? "labelled evaluation" : "descriptive run (no labels used)"} · ${stamp(exp.created_at)}`}
        actions={<Button size="sm" icon={<ArrowsClockwise size={13} />} busy={rerunning} onClick={onRerun}>Repeat</Button>}
      />
      <div className="grid grid-cols-2 gap-4 border-t border-[var(--hairline)] p-5 sm:grid-cols-4">
        <Stat label="Rows accepted" sub={`${d.rows_rejected.toLocaleString()} rejected`}>{d.rows_accepted.toLocaleString()}</Stat>
        <Stat label="Time span">{num(d.span_hours, 2)} h</Stat>
        <Stat label="Detector warm-up" sub="no alerts possible before this">{seconds(d.detector_warmup_seconds)}</Stat>
        <Stat label="Result fingerprint" sub="same inputs, same value"><span className="text-[14px]">{exp.results_sha256.slice(0, 12)}</span></Stat>
      </div>
      {exp.rerun_of && (
        <p role="status" className={cx("border-t border-[var(--hairline)] px-5 py-3 text-[12.5px]", exp.reproduced ? "text-signal" : "text-sev-critical")}>
          {exp.reproduced ? `Reproduced: identical to ${exp.rerun_of}.` : `Differs from ${exp.rerun_of}: the results are not identical.`}
        </p>
      )}
      {d.warnings.length > 0 && <ul className="list-disc space-y-1 border-t border-[var(--hairline)] py-3 pl-9 pr-5 text-[12.5px] text-sev-medium">{d.warnings.map((w) => <li key={w}>{w}</li>)}</ul>}
      <ul className="divide-y divide-[var(--hairline)] border-t border-[var(--hairline)]">
        {exp.result.methods.map((m) => <MethodCard key={m.method} m={m} titles={titles} />)}
      </ul>
      <p className="border-t border-[var(--hairline)] px-5 py-3 text-[11.5px] leading-relaxed text-fg-dim">{exp.disclaimer} Identifiers were replaced by keyed pseudonyms; the original upload is kept unchanged on this server.</p>
    </Panel>
  );
}

export default function Research() {
  const qc = useQueryClient();
  const me = useMe();
  const info = useQuery({ queryKey: ["research-info"], queryFn: api.researchInfo, staleTime: 5 * 60_000 });
  const experiments = useQuery({ queryKey: ["research-experiments"], queryFn: api.researchExperiments });
  const fileInput = useRef<HTMLInputElement>(null);

  const [ack, setAck] = useState(false);
  const [upload, setUpload] = useState<ResearchUploadResult | null>(null);
  const [draft, setDraft] = useState<MappingDraft | null>(null);
  const [report, setReport] = useState<ResearchReport | null>(null);
  const [mode, setMode] = useState<"auto" | "descriptive">("auto");
  const [methods, setMethods] = useState<string[]>(["current"]);
  const [result, setResult] = useState<ResearchExperiment | null>(null);
  const [picked, setPicked] = useState<string[]>([]);

  const can = me.data?.can ?? { operate: false, admin: false };
  const mapping = useMemo(() => (draft ? buildMapping(draft) : null), [draft]);
  const kind = draft?.kind ?? "app";

  const uploadM = useMutation({
    mutationFn: (file: File) => api.researchUpload(file),
    onSuccess: (r) => {
      setUpload(r);
      setReport(null);
      setResult(null);
      setDraft(info.data ? emptyDraft("app", r.inspection.columns.map((c) => c.name), info.data.kinds.app.fields) : null);
    },
    onError: (e) => toast.error("Upload refused", errMsg(e)),
  });
  const validateM = useMutation({
    mutationFn: () => api.researchValidate(upload!.upload.id, mapping!),
    onSuccess: setReport,
    onError: (e) => toast.error("Could not validate", errMsg(e)),
  });
  const runM = useMutation({
    mutationFn: () => api.researchRun({ upload_id: upload!.upload.id, mapping: mapping!, methods, mode }),
    onSuccess: (r) => {
      setResult(r);
      void qc.invalidateQueries({ queryKey: ["research-experiments"] });
    },
    onError: (e) => toast.error("Evaluation not run", errMsg(e)),
  });
  const rerunM = useMutation({
    mutationFn: (id: string) => api.researchRerun(id),
    onSuccess: (r) => {
      setResult(r);
      void qc.invalidateQueries({ queryKey: ["research-experiments"] });
    },
    onError: (e) => toast.error("Could not repeat", errMsg(e)),
  });
  const compareM = useMutation({ mutationFn: () => api.researchCompare(picked[0]!, picked[1]!), onError: (e) => toast.error("Could not compare", errMsg(e)) });

  const changeDraft = (d: MappingDraft) => {
    setDraft(d);
    setReport(null);
  };
  const onFile = (file?: File) => {
    if (!file || !info.data) return;
    const problem = precheckFile(file, info.data.formats, info.data.limits.max_upload_mb);
    if (problem) {
      toast.error("Upload refused", problem);
      return;
    }
    uploadM.mutate(file);
  };
  const open = async (id: string) => {
    try {
      setResult(await api.researchExperiment(id));
    } catch (e) {
      toast.error("Could not open that experiment", errMsg(e));
    }
  };

  if (info.isLoading) return <SkeletonRows rows={6} />;
  if (info.error || !info.data) return <ErrorState error={info.error} onRetry={() => info.refetch()} />;
  if (!info.data.enabled) {
    return <EmptyState title="Dataset evaluation is turned off" body="This server has user-dataset evaluation disabled (RESEARCH_ENABLED=false)." />;
  }
  const data = info.data;
  const labelled = !!mapping?.label;
  const appOnly = kind !== "app";

  return (
    <div className="space-y-5">
      <PageHeader
        title="Your data"
        description="Run the detector on your own CSV or JSON Lines file and, if it has ground-truth labels, measure precision, recall, false alarms and detection delay. Research prototype: use synthetic or properly de-identified data only."
        actions={<span className="inline-flex items-center gap-1.5 text-[12px] text-fg-dim"><Flask size={14} /> No external services are called</span>}
      />

      {!can.operate && me.data && (
        <p role="status" className="rounded-[12px] bg-ink-850 px-4 py-2.5 text-[12.5px] text-fg-muted shadow-[inset_0_0_0_1px_var(--hairline)]">
          Uploading and running needs the operator role. You can view saved experiments. Enter a token under Settings, API access.
        </p>
      )}

      <PrivacyNotice info={data} ack={ack} onAck={setAck} />

      <Step n={1} title="Choose a file">
        <div className="flex flex-wrap items-center gap-3">
          <input ref={fileInput} type="file" accept={data.formats.join(",")} className="sr-only" aria-label="Dataset file" disabled={!ack || !can.operate}
            onChange={(e) => { onFile(e.target.files?.[0]); e.target.value = ""; }} />
          <Button icon={<UploadSimple size={14} />} busy={uploadM.isPending} disabled={!ack || !can.operate} onClick={() => fileInput.current?.click()}>
            Select CSV or JSON Lines file
          </Button>
          {!ack && <span className="text-[12px] text-fg-dim">Confirm the notice above first.</span>}
          {upload && <span className="text-[12.5px] text-fg-muted">{upload.upload.filename} · {formatBytes(upload.upload.size_bytes)} · {upload.inspection.format.toUpperCase()} · {upload.inspection.rows_usable.toLocaleString()} usable rows</span>}
        </div>
        {upload?.inspection.rows_truncated_at_limit && <p className="mt-2 text-[12px] text-sev-medium">The file has more rows than the limit; only the first {data.limits.max_rows.toLocaleString()} are read.</p>}
      </Step>

      {upload && draft && mapping && (
        <>
          <Step n={2} title="Preview">
            <p className="mb-3 text-[12px] text-fg-dim">{upload.inspection.preview_note}</p>
            <div className="overflow-x-auto">
              <table className="w-full min-w-[520px] text-left text-[12px]">
                <caption className="sr-only">First rows of the file</caption>
                <thead className="text-fg-dim"><tr>{upload.inspection.columns.map((c) => (
                  <th key={c.name} scope="col" className="px-2 py-1.5 font-normal">
                    <span className="text-fg">{c.name}</span><span className="block text-[10.5px]">{c.kind}{c.masked_in_preview ? " · masked" : ""}</span>
                  </th>))}</tr></thead>
                <tbody className="divide-y divide-[var(--hairline)]">
                  {upload.inspection.preview_rows.map((r) => (
                    <tr key={String(r.row)}>{upload.inspection.columns.map((c) => <td key={c.name} className="max-w-[180px] truncate px-2 py-1.5 font-mono text-fg-muted">{String(r[c.name] ?? "")}</td>)}</tr>
                  ))}
                </tbody>
              </table>
            </div>
            {upload.inspection.sensitive_columns.length > 0 && (
              <p className="mt-3 text-[12px] text-sev-medium">Columns that look sensitive: {upload.inspection.sensitive_columns.join(", ")}. Do not map them; consider removing them from the file.</p>
            )}
          </Step>

          <Step n={3} title="Map your columns">
            <MappingEditor info={data} upload={upload} draft={draft} setDraft={changeDraft} />
          </Step>

          <Step n={4} title="Validate">
            <div className="space-y-4">
              <Button busy={validateM.isPending} disabled={!can.operate} onClick={() => validateM.mutate()}>Validate mapping</Button>
              {report && <ReportView report={report} />}
            </div>
          </Step>

          <Step n={5} title="Run">
            <div className="space-y-4">
              <Field label="Evaluation mode" htmlFor="mode" hint={labelled
                ? "Labels are mapped: the run measures precision, recall, false-alarm rate and delay against them."
                : "No labels are mapped: the run lists the incidents the detector found. Nothing is measured."}>
                <Segmented<"auto" | "descriptive"> label="Evaluation mode" value={mode} onChange={setMode}
                  options={[{ value: "auto", label: labelled ? "Labelled evaluation" : "Descriptive" }, { value: "descriptive", label: "Descriptive only" }]} />
              </Field>
              <fieldset>
                <legend className="mb-1 text-[12.5px] font-medium text-fg-muted">Methods</legend>
                <div className="grid gap-1.5 sm:grid-cols-2">
                  {data.methods.map((m) => {
                    const disabled = appOnly && m.service_metric_only;
                    return (
                      <label key={m.id} className={cx("flex items-start gap-2 text-[12.5px]", disabled && "opacity-50")}>
                        <input type="checkbox" disabled={disabled} checked={methods.includes(m.id) && !disabled}
                          onChange={(e) => setMethods(e.target.checked ? [...methods, m.id] : methods.filter((x) => x !== m.id))} />
                        <span><span className="text-fg">{m.title}</span><span className="block text-fg-dim">{disabled ? "Service-log datasets only." : m.description}</span></span>
                      </label>
                    );
                  })}
                </div>
              </fieldset>
              <Button variant="primary" busy={runM.isPending} disabled={!can.operate || !report?.ok || methods.length === 0} onClick={() => runM.mutate()}>
                Run evaluation
              </Button>
              {!report?.ok && <p className="text-[12px] text-fg-dim">Validate a correct mapping first. Changing the mapping clears the validation.</p>}
              {runM.isPending && <p role="status" aria-live="polite" className="text-[12.5px] text-fg-muted">Running. Large files can take about a minute.</p>}
            </div>
          </Step>
        </>
      )}

      {result && <ExperimentView exp={result} info={data} rerunning={rerunM.isPending} onRerun={() => rerunM.mutate(result.id)} />}

      <Panel>
        <PanelHeader title="Saved experiments" description="Each keeps its exact mapping, methods and results so it can be repeated and compared. Select two to compare." />
        {experiments.isLoading ? <SkeletonRows rows={3} /> : experiments.error ? (
          <ErrorState error={experiments.error} onRetry={() => experiments.refetch()} />
        ) : !experiments.data?.items.length ? (
          <EmptyState title="No experiments yet" body="Run an evaluation above. Experiments are removed after the retention period." className="py-10" />
        ) : (
          <>
            <ul className="divide-y divide-[var(--hairline)] border-t border-[var(--hairline)]">
              {experiments.data.items.map((e) => (
                <li key={e.id} className="flex items-center gap-3 px-5 py-2.5 text-[12.5px]">
                  <input type="checkbox" aria-label={`Select ${e.id} to compare`} checked={picked.includes(e.id)}
                    onChange={(ev) => setPicked(ev.target.checked ? [...picked, e.id].slice(-2) : picked.filter((x) => x !== e.id))} />
                  <button type="button" onClick={() => open(e.id)} className="min-w-0 flex-1 truncate text-left text-fg hover:underline">
                    {e.filename} <span className="text-fg-dim">· {e.mode} · {e.methods.join(", ")}</span>
                  </button>
                  <span className="hidden font-mono text-fg-dim sm:inline">{e.results_sha256.slice(0, 8)}</span>
                  <span className="hidden text-fg-dim sm:inline">{stamp(e.created_at)}</span>
                </li>
              ))}
            </ul>
            <div className="border-t border-[var(--hairline)] px-5 py-3">
              <Button size="sm" disabled={picked.length !== 2} busy={compareM.isPending} onClick={() => compareM.mutate()}>Compare selected</Button>
              {compareM.data && (
                <div className="mt-3 space-y-2 text-[12.5px]">
                  <p className="text-fg-muted">
                    {compareM.data.results_identical ? "The two experiments have identical results." : "The two experiments differ."}{" "}
                    Same upload: {compareM.data.same_upload ? "yes" : "no"}. Same mapping: {compareM.data.same_mapping ? "yes" : "no"}. Same methods: {compareM.data.same_methods ? "yes" : "no"}.
                  </p>
                  <table className="w-full text-left">
                    <caption className="sr-only">Comparison of two experiments</caption>
                    <thead className="text-[11.5px] text-fg-dim"><tr><th scope="col" className="py-1 font-normal">Method</th><th scope="col" className="py-1 font-normal">Metric</th><th scope="col" className="py-1 font-normal">A</th><th scope="col" className="py-1 font-normal">B</th></tr></thead>
                    <tbody className="divide-y divide-[var(--hairline)]">
                      {compareM.data.rows.map((r) => <tr key={r.method + r.metric}><td className="py-1">{r.method}</td><td className="py-1">{r.metric}</td><td className="py-1 font-mono">{num(r.a, 3)}</td><td className="py-1 font-mono">{num(r.b, 3)}</td></tr>)}
                    </tbody>
                  </table>
                  <p className="text-[11.5px] text-fg-dim">{compareM.data.note}</p>
                </div>
              )}
            </div>
          </>
        )}
      </Panel>
    </div>
  );
}
