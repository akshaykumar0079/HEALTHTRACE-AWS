import { useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { useQuery, keepPreviousData } from "@tanstack/react-query";
import { useVirtualizer } from "@tanstack/react-virtual";
import { ArrowRight, Broadcast, MagnifyingGlass, Pause, X } from "@phosphor-icons/react";
import { api } from "@/lib/api";
import { useLive } from "@/lib/live";
import type { LogRecord } from "@/lib/types";
import { KIND_LABEL, num, stamp } from "@/lib/format";
import { Button, EmptyState, ErrorState, PageHeader, Panel, SeverityBadge, Skeleton, cx, inputClass } from "@/components/ui";
import { LogLine } from "@/components/domain";

const QUICK = [
  { label: "Errors", q: "level:ERROR" },
  { label: "Timeouts", q: "timeout" },
  { label: "Urgent", q: "priority:urgent level:ERROR" },
  { label: "Prior auth", q: "service:prior_auth" },
  { label: "Eligibility", q: "service:eligibility" },
  { label: "Record exports", q: "action:EXPORT_RECORDS" },
  { label: "Audit trail", q: "type:audit" },
];

function Detail({ record, onClose }: { record: LogRecord; onClose: () => void }) {
  const { data, isLoading, error } = useQuery({ queryKey: ["log-context", record.seq], queryFn: () => api.logContext(record.seq) });
  const fields = Object.entries(record).filter(([k]) => k !== "seq");
  return (
    <aside className="flex h-full flex-col" aria-label="Log event detail">
      <header className="flex items-start justify-between gap-3 border-b border-[var(--hairline)] px-5 py-4">
        <div className="min-w-0">
          <p className="font-mono text-[11.5px] text-fg-dim">event #{record.seq}</p>
          <h2 className="mt-1 text-[14px] font-medium leading-snug text-fg">{record.msg}</h2>
          <p className="mt-1 font-mono text-[11.5px] text-fg-dim">{stamp(record.ts)}</p>
        </div>
        <button onClick={onClose} className="grid size-7 shrink-0 place-items-center rounded-lg text-fg-dim hover:bg-ink-750 hover:text-fg" aria-label="Close detail">
          <X size={14} />
        </button>
      </header>
      <div className="flex-1 space-y-6 overflow-y-auto p-5">
        <section>
          <h3 className="text-[12px] text-fg-dim">Complete event</h3>
          <pre className="mt-2 overflow-x-auto rounded-[12px] bg-ink-950 p-3.5 font-mono text-[11.5px] leading-relaxed text-fg-muted shadow-[inset_0_0_0_1px_var(--hairline)]">
            {JSON.stringify(Object.fromEntries(fields), null, 2)}
          </pre>
        </section>
        {record.type === "app" && (
          <section className="grid grid-cols-2 gap-3 text-[12.5px]">
            <div><p className="text-[11px] text-fg-dim">Request ID</p><p className="font-mono text-fg">{record.request_id}</p></div>
            <div><p className="text-[11px] text-fg-dim">Counts as error</p><p className="font-mono text-fg">{record.is_error ? "yes" : "no"}</p></div>
          </section>
        )}
        <section>
          <h3 className="text-[12px] text-fg-dim">Related anomaly</h3>
          {isLoading ? <Skeleton className="mt-2 h-10" /> : data?.related_alerts.length ? (
            <ul className="mt-2 space-y-2">
              {data.related_alerts.map((a) => (
                <li key={`${a.id}-${a.ts}`}>
                  <Link to={a.incident_id ? `/app/incidents/${a.incident_id}` : "/app/alerts"} className="flex items-center gap-2 rounded-[10px] bg-ink-800 px-3 py-2 text-[12.5px] text-fg-muted hover:text-fg">
                    <SeverityBadge severity={a.severity} size="sm" />
                    <span className="flex-1 truncate">{KIND_LABEL[a.kind]}</span>
                    <ArrowRight size={12} />
                  </Link>
                </li>
              ))}
            </ul>
          ) : (
            <p className="mt-1.5 text-[12.5px] text-fg-dim">No alert for this service within two minutes of this event.</p>
          )}
        </section>
        <section>
          <h3 className="text-[12px] text-fg-dim">Surrounding events</h3>
          {error ? (
            <p className="mt-1.5 text-[12.5px] text-fg-dim">{error instanceof Error ? error.message : "Unavailable"}</p>
          ) : isLoading ? (
            <Skeleton className="mt-2 h-32" />
          ) : (
            <div className="-mx-4 mt-2">
              {data?.before.map((r) => <LogLine key={r.seq} record={r} />)}
              <div className="mx-4 my-0.5 rounded-lg ring-1 ring-signal/40"><LogLine record={record} selected /></div>
              {data?.after.map((r) => <LogLine key={r.seq} record={r} />)}
            </div>
          )}
        </section>
      </div>
    </aside>
  );
}

export default function Logs() {
  const [params, setParams] = useSearchParams();
  const initial = params.get("q") ?? "";
  const [draft, setDraft] = useState(initial);
  const [query, setQuery] = useState(initial);
  const [live, setLive] = useState(true);
  const [selected, setSelected] = useState<LogRecord | null>(null);
  const lastLog = useLive((s) => s.logs[0]?.seq);
  const inputRef = useRef<HTMLInputElement>(null);

  const { data, isLoading, error, refetch, isFetching } = useQuery({
    queryKey: ["logs", query, live ? lastLog : "paused"],
    queryFn: () => api.logs(query, 1000),
    placeholderData: keepPreviousData,
  });

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "/" && document.activeElement?.tagName !== "INPUT") {
        e.preventDefault();
        inputRef.current?.focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const run = (q: string) => {
    setDraft(q);
    setQuery(q);
    setParams(q ? { q } : {}, { replace: true });
  };

  const events = data?.events ?? [];
  const scrollRef = useRef<HTMLDivElement>(null);
  const virtual = useVirtualizer({ count: events.length, getScrollElement: () => scrollRef.current, estimateSize: () => 29, overscan: 16 });

  return (
    <div>
      <PageHeader
        title="Logs"
        description={<>Search the most recent events held in memory. Terms combine with AND; use <span className="font-mono text-fg">field:value</span> for service, level, status, priority, type, user, action, request_id, role or region.</>}
        actions={
          <Button variant={live ? "secondary" : "primary"} icon={live ? <Pause size={15} /> : <Broadcast size={15} />} onClick={() => setLive((l) => !l)}>
            {live ? "Pause live" : "Go live"}
          </Button>
        }
      />
      <form
        onSubmit={(e) => {
          e.preventDefault();
          run(draft.trim());
        }}
        className="relative"
        role="search"
      >
        <MagnifyingGlass size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-fg-dim" />
        <label htmlFor="log-q" className="sr-only">Search logs</label>
        <input
          ref={inputRef}
          id="log-q"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          placeholder="timeout AND service:prior_auth"
          className={cx(inputClass, "h-12 rounded-[14px] pl-11 pr-28 font-mono text-[13.5px]")}
          autoComplete="off"
          spellCheck={false}
        />
        <div className="absolute right-2 top-1/2 flex -translate-y-1/2 items-center gap-2">
          <span className="kbd hidden sm:inline">/</span>
          <Button type="submit" size="sm" variant="primary">Search</Button>
        </div>
      </form>
      <div className="mt-3 flex flex-wrap gap-1.5">
        {QUICK.map((q) => (
          <button
            key={q.label}
            onClick={() => run(q.q)}
            className={cx(
              "h-7 rounded-full px-3 text-[12px] transition-colors",
              query === q.q ? "bg-signal-deep text-signal shadow-[inset_0_0_0_1px_rgb(86_220_200/0.35)]" : "bg-ink-800 text-fg-muted shadow-[inset_0_0_0_1px_var(--hairline)] hover:text-fg",
            )}
          >
            {q.label}
          </button>
        ))}
        {query && (
          <button onClick={() => run("")} className="h-7 rounded-full px-3 text-[12px] text-fg-dim hover:text-fg">
            Clear
          </button>
        )}
      </div>

      <div className="mt-5 grid gap-5 xl:grid-cols-[minmax(0,1fr)_420px]">
        <Panel className="overflow-hidden">
          <div className="flex items-center justify-between border-b border-[var(--hairline)] px-4 py-2.5 text-[11.5px] text-fg-dim">
            <span>
              <span className="font-mono text-fg">{num(events.length)}</span> matching events
              {data && <> in a buffer of <span className="font-mono">{num(data.buffer_size)}</span></>}
            </span>
            <span className={cx("font-mono", isFetching && "text-signal")}>{live ? "live" : "paused"}</span>
          </div>
          <div className="hidden grid-cols-[64px_44px_110px_1fr_auto] gap-3 border-b border-[var(--hairline)] px-4 py-2 font-mono text-[10.5px] text-fg-dim md:grid">
            <span>time</span><span>level</span><span>source</span><span>message</span><span>detail</span>
          </div>
          {isLoading ? (
            <div className="space-y-2 p-4">{Array.from({ length: 12 }, (_, i) => <Skeleton key={i} className="h-5" />)}</div>
          ) : error ? (
            <ErrorState error={error} onRetry={() => refetch()} />
          ) : events.length === 0 ? (
            <EmptyState icon={<MagnifyingGlass size={20} />} title="No events match" body={query ? `Nothing in the recent buffer matches "${query}".` : "No events have been read yet."} />
          ) : (
            <div ref={scrollRef} className="h-[min(640px,70vh)] overflow-y-auto">
              <div className="relative w-full" style={{ height: virtual.getTotalSize() }}>
                {virtual.getVirtualItems().map((row) => {
                  const r = events[row.index];
                  return (
                    <div key={r.seq} className="absolute inset-x-0" style={{ transform: `translateY(${row.start}px)` }}>
                      <LogLine record={r} onSelect={setSelected} selected={selected?.seq === r.seq} />
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </Panel>
        <Panel className="h-[min(720px,78vh)] overflow-hidden xl:sticky xl:top-20">
          {selected ? (
            <Detail key={selected.seq} record={selected} onClose={() => setSelected(null)} />
          ) : (
            <EmptyState title="Select an event" body="Its full record, surrounding events and any related anomaly appear here." className="h-full" />
          )}
        </Panel>
      </div>
    </div>
  );
}
