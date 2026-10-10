import { useEffect, useMemo, useRef, useState } from "react";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { CaretLeft, CaretRight, ClockCounterClockwise, Pause, Play, SkipBack, WifiSlash } from "@phosphor-icons/react";
import { api } from "@/lib/api";
import { useLive } from "@/lib/live";
import type { IncidentState, TimelineEntry, TimelineResponse, TimelineSource } from "@/lib/types";
import { stamp } from "@/lib/format";
import {
  PHASES,
  PHASE_LABEL,
  SOURCES,
  SOURCE_LABEL,
  clampCursor,
  countByPhase,
  coverageNotices,
  describeWindow,
  entriesUpTo,
  moveSelection,
  reconcileSelection,
  replayState,
  sortEntries,
  stepCursor,
} from "@/lib/timeline";
import { Button, EmptyState, ErrorState, Panel, PanelHeader, SeverityBadge, Skeleton, cx, inputClass } from "./ui";

const WINDOW_CHOICES = [5, 15, 30, 60, 180];
const REPLAY_MS = 700;

const clockMs = (iso: string) => {
  const d = new Date(iso);
  return `${d.toLocaleTimeString([], { hour12: false })}.${String(d.getMilliseconds()).padStart(3, "0")}`;
};

const NOTICE_TONE = {
  ok: "text-signal",
  warn: "text-sev-medium",
  info: "text-fg-dim",
} as const;

function ValueList({ values }: { values: Record<string, unknown> | null | undefined }) {
  if (!values || Object.keys(values).length === 0) return <span className="text-fg-dim">not available</span>;
  return (
    <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 font-mono text-[12px]">
      {Object.entries(values).map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="text-fg-dim">{k.replace(/_/g, " ")}</dt>
          <dd className="text-fg">{typeof v === "number" ? (Number.isInteger(v) ? v : v.toFixed(4)) : typeof v === "object" ? JSON.stringify(v) : String(v)}</dd>
        </div>
      ))}
    </dl>
  );
}

export function DetectionExplanationPanel({ data }: { data: TimelineResponse }) {
  const e = data.explanation;
  return (
    <section aria-labelledby="tm-detection" className="rounded-[12px] bg-ink-850 p-4 shadow-[inset_0_0_0_1px_var(--hairline)]">
      <h3 id="tm-detection" className="text-[13px] font-medium text-fg">Why this alert fired</h3>
      <p className="mt-1 text-[12.5px] leading-relaxed text-fg-muted">{e.rule_text}</p>
      {e.available ? (
        <div className="mt-3 grid gap-4 sm:grid-cols-2">
          <div><p className="mb-1 text-[11.5px] text-fg-dim">Observed</p><ValueList values={e.observed} /></div>
          <div><p className="mb-1 text-[11.5px] text-fg-dim">Baseline</p><ValueList values={e.baseline} /></div>
          <div><p className="mb-1 text-[11.5px] text-fg-dim">Threshold</p><ValueList values={e.threshold} /></div>
          <div>
            <p className="mb-1 text-[11.5px] text-fg-dim">Deviation</p>
            {e.deviation && typeof e.deviation === "object" ? <ValueList values={e.deviation as Record<string, unknown>} /> : <span className="font-mono text-[12px] text-fg">{e.deviation ?? "not available"}</span>}
          </div>
          {e.reason && <p className="sm:col-span-2 text-[12.5px] leading-relaxed text-fg-muted"><span className="text-fg-dim">Reason: </span>{e.reason}</p>}
        </div>
      ) : (
        <p className="mt-3 text-[12.5px] text-fg-dim" role="note">{e.note ?? "Detection values are not available for this incident."}</p>
      )}
    </section>
  );
}

function EntryDetail({ incidentId, entry }: { incidentId: number; entry: TimelineEntry }) {
  const { data, error, isLoading, refetch } = useQuery({
    queryKey: ["timeline-entry", incidentId, entry.id],
    queryFn: () => api.timelineEntry(incidentId, entry.id),
    retry: false,
  });
  return (
    <section aria-labelledby="tm-entry" className="rounded-[12px] bg-ink-850 p-4 shadow-[inset_0_0_0_1px_var(--hairline)]">
      <div className="flex flex-wrap items-center gap-2">
        <h3 id="tm-entry" className="text-[13px] font-medium text-fg">Selected event</h3>
        {entry.severity && <SeverityBadge severity={entry.severity} size="sm" />}
        <span className="rounded-full bg-ink-750 px-2 py-0.5 text-[11px] text-fg-muted">{SOURCE_LABEL[entry.source]}</span>
      </div>
      <dl className="mt-3 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-[12.5px]">
        <dt className="text-fg-dim">Time</dt><dd className="font-mono text-fg">{stamp(entry.ts)} <span className="text-fg-dim">({clockMs(entry.ts)})</span></dd>
        <dt className="text-fg-dim">Type</dt><dd className="text-fg">{entry.event_type.replace(/_/g, " ")}</dd>
        <dt className="text-fg-dim">Service</dt><dd className="text-fg">{entry.service ?? "not applicable"}</dd>
        <dt className="text-fg-dim">Component</dt><dd className="text-fg">{entry.component ?? "not recorded"}</dd>
        <dt className="text-fg-dim">Phase</dt><dd className="text-fg">{PHASE_LABEL[entry.phase]}</dd>
        {entry.level && (<><dt className="text-fg-dim">Log level</dt><dd className="font-mono text-fg">{entry.level}</dd></>)}
        <dt className="text-fg-dim">Summary</dt><dd className="text-fg-muted">{entry.summary}</dd>
      </dl>
      {(entry.observed || entry.baseline) && (
        <div className="mt-3 grid gap-4 sm:grid-cols-2">
          <div><p className="mb-1 text-[11.5px] text-fg-dim">Observed</p><ValueList values={entry.observed ?? null} /></div>
          <div>
            <p className="mb-1 text-[11.5px] text-fg-dim">Baseline</p>
            <ValueList values={entry.baseline ?? null} />
            {entry.breaches_threshold != null && (
              <p className="mt-1 text-[11.5px] text-fg-dim">{entry.breaches_threshold ? "Breaches" : "Within"} the detection threshold{entry.z != null ? ` (z = ${entry.z.toFixed(1)})` : ""}.</p>
            )}
          </div>
        </div>
      )}
      <div className="mt-3">
        <p className="mb-1 text-[11.5px] text-fg-dim">Raw record (synthetic, masked)</p>
        {isLoading ? <Skeleton className="h-24" /> : error ? (
          <ErrorState error={error} onRetry={() => refetch()} className="py-6" />
        ) : (
          <>
            <pre tabIndex={0} aria-label="Raw record" className="max-h-56 overflow-auto rounded-[10px] bg-ink-900 p-3 font-mono text-[11.5px] leading-relaxed text-fg-muted">{JSON.stringify(data?.raw, null, 2)}</pre>
            <p className="mt-1 text-[11.5px] text-fg-dim">{data?.note}</p>
          </>
        )}
      </div>
    </section>
  );
}

export function TimeMachine({ incidentId, state }: { incidentId: number; state: IncidentState }) {
  const connection = useLive((s) => s.connection);
  const [before, setBefore] = useState(15);
  const [after, setAfter] = useState(15);
  const [sources, setSources] = useState<TimelineSource[]>([...SOURCES]);
  const [pickedId, setSelected] = useState<string | null>(null);
  const [replaying, setReplaying] = useState(false);
  const [playing, setPlaying] = useState(false);
  const [cursor, setCursor] = useState(-1);
  const listRef = useRef<HTMLDivElement>(null);

  const { data, error, isLoading, isFetching, refetch } = useQuery({
    queryKey: ["timeline", incidentId, before, after, sources.join(",")],
    queryFn: () => api.timeline(incidentId, { before_minutes: before, after_minutes: after, sources: sources.join(",") }),
    placeholderData: keepPreviousData,
    refetchInterval: state === "RESOLVED" || replaying ? false : 20_000,
    enabled: sources.length > 0,
  });

  const sorted = useMemo(() => sortEntries(data?.entries ?? []), [data]);
  const visible = useMemo(() => (replaying ? entriesUpTo(sorted, cursor) : sorted), [replaying, sorted, cursor]);
  const counts = useMemo(() => countByPhase(visible), [visible]);
  const rs = useMemo(() => replayState(visible), [visible]);
  // The selection never silently jumps to another event: if it leaves the view it is simply cleared.
  const selected = useMemo(() => reconcileSelection(pickedId, visible), [pickedId, visible]);
  const selectedEntry = visible.find((e) => e.id === selected) ?? null;

  useEffect(() => {
    if (!playing) return;
    const t = window.setInterval(() => {
      setCursor((c) => {
        const next = stepCursor(c, sorted.length, 1);
        if (next === c) setPlaying(false);
        return next;
      });
    }, REPLAY_MS);
    return () => window.clearInterval(t);
  }, [playing, sorted.length]);

  const startReplay = () => {
    setReplaying(true);
    setCursor(-1);
    setPlaying(false);
  };
  const stopReplay = () => {
    setReplaying(false);
    setPlaying(false);
    setCursor(-1);
  };

  const toggleSource = (s: TimelineSource) =>
    setSources((cur) => (cur.includes(s) ? cur.filter((x) => x !== s) : [...cur, s]));

  const onListKey = (e: React.KeyboardEvent) => {
    if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
    e.preventDefault();
    const next = moveSelection(selected, visible, e.key === "ArrowDown" ? 1 : -1);
    setSelected(next);
    if (next) listRef.current?.querySelector<HTMLElement>(`[data-entry="${CSS.escape(next)}"]`)?.focus();
  };

  const notices = data ? coverageNotices(data.coverage, data.count) : [];

  return (
    <Panel>
      <PanelHeader
        title={<span className="inline-flex items-center gap-2"><ClockCounterClockwise size={16} /> Incident Time Machine</span>}
        description={`Stored events around this incident (${describeWindow(before, after)}). Read-only: replaying never changes the stored records.`}
        actions={isFetching ? <span className="text-[12px] text-fg-dim" aria-live="polite">Updating...</span> : null}
      />

      {connection !== "live" && (
        <p role="status" className="mx-5 mb-3 flex items-center gap-2 rounded-[12px] bg-[#e3b35a0d] px-4 py-2.5 text-[12.5px] text-fg-muted shadow-[inset_0_0_0_1px_rgb(227_179_90/0.25)]">
          <WifiSlash size={16} className="shrink-0 text-sev-medium" />
          Live updates are {connection === "offline" ? "offline" : "reconnecting"}. This timeline shows the last data loaded.
        </p>
      )}

      <div className="flex flex-wrap items-end gap-x-5 gap-y-3 border-t border-[var(--hairline)] px-5 py-4">
        <div>
          <label htmlFor="tm-before" className="mb-1.5 block text-[11.5px] text-fg-dim">Before</label>
          <select id="tm-before" value={before} onChange={(e) => setBefore(Number(e.target.value))} className={cx(inputClass, "w-28")}>
            {WINDOW_CHOICES.map((m) => <option key={m} value={m}>{m >= 60 ? `${m / 60} h` : `${m} min`}</option>)}
          </select>
        </div>
        <div>
          <label htmlFor="tm-after" className="mb-1.5 block text-[11.5px] text-fg-dim">After</label>
          <select id="tm-after" value={after} onChange={(e) => setAfter(Number(e.target.value))} className={cx(inputClass, "w-28")}>
            {WINDOW_CHOICES.map((m) => <option key={m} value={m}>{m >= 60 ? `${m / 60} h` : `${m} min`}</option>)}
          </select>
        </div>
        <fieldset>
          <legend className="mb-1.5 text-[11.5px] text-fg-dim">Show</legend>
          <div className="flex flex-wrap gap-1.5">
            {SOURCES.map((s) => {
              const on = sources.includes(s);
              return (
                <button
                  key={s}
                  type="button"
                  aria-pressed={on}
                  onClick={() => toggleSource(s)}
                  className={cx(
                    "h-8 rounded-full px-3 text-[12px] font-medium transition-colors",
                    on ? "bg-signal text-ink-950" : "bg-ink-800 text-fg-muted shadow-[inset_0_0_0_1px_var(--hairline)] hover:text-fg",
                  )}
                >
                  {SOURCE_LABEL[s]}
                </button>
              );
            })}
          </div>
        </fieldset>
        <div className="ml-auto">
          {replaying ? (
            <Button size="sm" onClick={stopReplay}>Exit replay</Button>
          ) : (
            <Button size="sm" onClick={startReplay} disabled={sorted.length === 0} icon={<Play size={14} />}>Replay</Button>
          )}
        </div>
      </div>

      {replaying && (
        <div className="border-t border-[var(--hairline)] px-5 py-4" role="group" aria-label="Replay controls">
          <div className="flex flex-wrap items-center gap-2">
            <Button size="sm" variant="ghost" aria-label="Back to start" onClick={() => { setPlaying(false); setCursor(-1); }} icon={<SkipBack size={14} />} />
            <Button size="sm" variant="ghost" aria-label="Step back" onClick={() => { setPlaying(false); setCursor((c) => stepCursor(c, sorted.length, -1)); }} icon={<CaretLeft size={14} />} />
            <Button size="sm" aria-label={playing ? "Pause replay" : "Play replay"} onClick={() => { if (cursor >= sorted.length - 1) setCursor(-1); setPlaying((p) => !p); }} icon={playing ? <Pause size={14} /> : <Play size={14} />}>
              {playing ? "Pause" : "Play"}
            </Button>
            <Button size="sm" variant="ghost" aria-label="Step forward" onClick={() => { setPlaying(false); setCursor((c) => stepCursor(c, sorted.length, 1)); }} icon={<CaretRight size={14} />} />
            <label htmlFor="tm-scrub" className="sr-only">Replay position</label>
            <input
              id="tm-scrub"
              type="range"
              min={0}
              max={sorted.length}
              value={cursor + 1}
              onChange={(e) => { setPlaying(false); setCursor(clampCursor(Number(e.target.value) - 1, sorted.length)); }}
              className="min-w-[160px] flex-1 accent-[var(--color-signal)]"
            />
          </div>
          <p className="mt-2 text-[12.5px] text-fg-muted" role="status" aria-live="polite">
            {visible.length} of {sorted.length} events replayed
            {rs.at ? ` (up to ${clockMs(rs.at)})` : ""}. Status at this point: <span className="font-medium text-fg">{rs.status.replace(/_/g, " ").toLowerCase()}</span>
            {rs.severity ? `, severity ${rs.severity}` : ""}, {rs.occurrences} alert{rs.occurrences === 1 ? "" : "s"} so far.
          </p>
        </div>
      )}

      {sources.length === 0 ? (
        <EmptyState title="Choose at least one source" body="Turn on lifecycle, alerts, evidence or window metrics to see events." className="py-10" />
      ) : isLoading ? (
        <div className="space-y-2 border-t border-[var(--hairline)] p-5"><Skeleton className="h-8" /><Skeleton className="h-8" /><Skeleton className="h-8" /></div>
      ) : error ? (
        <ErrorState error={error} onRetry={() => refetch()} />
      ) : !data ? null : (
        <div className="border-t border-[var(--hairline)]">
          <ul className="space-y-1.5 px-5 pt-4" aria-label="Data coverage">
            {notices.map((n) => (
              <li key={n.title} className="text-[12.5px] leading-relaxed">
                <span className={cx("font-medium", NOTICE_TONE[n.tone])}>{n.title}.</span>{" "}
                <span className="text-fg-dim">{n.body}</span>
              </li>
            ))}
            {data.notes.map((n) => <li key={n} className="text-[12.5px] text-fg-dim">{n}</li>)}
          </ul>

          <div className="grid gap-5 p-5 xl:grid-cols-[minmax(0,1.1fr)_minmax(0,1fr)]">
            <div>
              <p className="mb-2 text-[12px] text-fg-dim" aria-live="polite">
                {visible.length} event{visible.length === 1 ? "" : "s"}: {counts.before} before, {counts.during} during, {counts.after} after
              </p>
              {visible.length === 0 ? (
                <EmptyState title={replaying ? "Nothing has happened yet" : "No stored events in this window"} body={replaying ? "Step forward to replay the first stored event." : "Widen the window or turn on more sources. Nothing is inferred or generated for missing history."} className="py-10" />
              ) : (
                <div ref={listRef} onKeyDown={onListKey} role="list" aria-label="Timeline events" className="max-h-[480px] overflow-y-auto rounded-[12px] shadow-[inset_0_0_0_1px_var(--hairline)]">
                  {PHASES.map((phase) => {
                    const rows = visible.filter((e) => e.phase === phase);
                    if (rows.length === 0) return null;
                    return (
                      <div key={phase} role="listitem">
                        <h3 className="sticky top-0 z-10 bg-ink-850 px-4 py-1.5 text-[11px] font-medium uppercase tracking-wide text-fg-dim">{PHASE_LABEL[phase]}</h3>
                        <ul>
                          {rows.map((e) => {
                            const on = e.id === selected;
                            return (
                              <li key={e.id}>
                                <button
                                  type="button"
                                  data-entry={e.id}
                                  aria-pressed={on}
                                  onClick={() => setSelected(on ? null : e.id)}
                                  className={cx(
                                    "flex w-full items-start gap-3 border-t border-[var(--hairline)] px-4 py-2 text-left text-[12.5px] transition-colors",
                                    on ? "bg-ink-750" : "hover:bg-ink-800/60",
                                  )}
                                >
                                  <span className="w-[86px] shrink-0 font-mono text-[11.5px] text-fg-dim">{clockMs(e.ts)}</span>
                                  <span className="min-w-0 flex-1">
                                    <span className="flex flex-wrap items-center gap-1.5">
                                      <span className="rounded-full bg-ink-750 px-2 py-0.5 text-[10.5px] text-fg-muted">{SOURCE_LABEL[e.source]}</span>
                                      {e.severity && <SeverityBadge severity={e.severity} size="sm" />}
                                      {e.related && <span className="text-[10.5px] text-fg-dim">same {e.service ? "service" : "user"}, other incident</span>}
                                    </span>
                                    <span className="mt-0.5 block break-words text-fg-muted">{e.summary}</span>
                                    {(e.service || e.component) && <span className="block text-[11px] text-fg-dim">{[e.service, e.component && e.component !== e.service ? e.component : null].filter(Boolean).join(" / ")}</span>}
                                  </span>
                                </button>
                              </li>
                            );
                          })}
                        </ul>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
            <div className="space-y-4">
              {selectedEntry ? <EntryDetail incidentId={incidentId} entry={selectedEntry} /> : (
                <p className="rounded-[12px] bg-ink-850 p-4 text-[12.5px] text-fg-dim shadow-[inset_0_0_0_1px_var(--hairline)]">
                  Select an event to see its time, component, raw synthetic record and how it compares with the baseline. Arrow keys move through the list.
                </p>
              )}
              <DetectionExplanationPanel data={data} />
            </div>
          </div>
        </div>
      )}
    </Panel>
  );
}

