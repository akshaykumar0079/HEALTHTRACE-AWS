import { useMemo, useState } from "react";
import { Link } from "react-router";
import { Pause, Play } from "@phosphor-icons/react";
import { useLive } from "@/lib/live";
import { Button, EmptyState, PageHeader, Panel, Segmented, SkeletonRows, cx, inputClass } from "@/components/ui";
import { LogLine } from "@/components/domain";
import { SimulatedBadge, StatusStrip, useFreshness } from "@/components/StatusStrip";

const SHOWN = 300; // rows rendered; the store itself keeps at most 600

export default function LiveEvents() {
  const logs = useLive((s) => s.logs);
  const hydrated = useLive((s) => s.hydrated);
  const paused = useLive((s) => s.logsPaused);
  const held = useLive((s) => s.pausedBuffer.length);
  const dropped = useLive((s) => s.pausedDropped);
  const setPaused = useLive((s) => s.setLogsPaused);
  const freshness = useFreshness();
  const [level, setLevel] = useState<"all" | "ERROR" | "WARN" | "INFO">("all");
  const [text, setText] = useState("");

  const rows = useMemo(() => {
    const t = text.trim().toLowerCase();
    return logs
      .filter((r) => (level === "all" || r.level === level) && (!t || `${r.msg} ${r.type === "app" ? r.service : r.user_id}`.toLowerCase().includes(t)))
      .slice(0, SHOWN);
  }, [logs, level, text]);

  return (
    <div className="space-y-5">
      <PageHeader
        title="Live events"
        description="The raw, parsed log stream as it arrives. These are not incidents: detection groups the ones that matter into Incidents."
        actions={<SimulatedBadge />}
      />
      <StatusStrip />
      <Panel>
        <div className="flex flex-wrap items-end gap-4 p-4">
          <div className="min-w-[200px] flex-1">
            <label htmlFor="events-filter" className="mb-1.5 block text-[11.5px] text-fg-dim">Filter</label>
            <input id="events-filter" type="search" value={text} onChange={(e) => setText(e.target.value)} placeholder="Message, service or user" className={inputClass} maxLength={100} />
          </div>
          <div>
            <p className="mb-1.5 text-[11.5px] text-fg-dim" id="lvl">Level</p>
            <Segmented label="Level" size="sm" value={level} options={[{ value: "all", label: "All" }, { value: "ERROR", label: "Error" }, { value: "WARN", label: "Warn" }, { value: "INFO", label: "Info" }]} onChange={setLevel} />
          </div>
          <Button variant={paused ? "primary" : "secondary"} onClick={() => setPaused(!paused)} icon={paused ? <Play size={14} weight="fill" /> : <Pause size={14} weight="fill" />}>
            {paused ? (held ? `Resume · ${held} new event${held === 1 ? "" : "s"}` : "Resume") : "Pause"}
          </Button>
        </div>
        {paused && (
          <p role="status" className="border-t border-[var(--hairline)] px-4 py-2 text-[12px] text-fg-muted">
            Paused. New events are held ({held}{dropped ? `, ${dropped} older held events dropped past the buffer limit` : ""}) and appear when you resume. Detection and incidents are not paused.
          </p>
        )}
        {freshness === "stale" && !paused && (
          <p role="status" className="border-t border-[var(--hairline)] px-4 py-2 text-[12px] text-sev-medium">
            Connected, but no recent log events are arriving. The list below is older data.
          </p>
        )}
      </Panel>

      <Panel>
        <div className="flex items-center justify-between px-5 py-3 text-[12px] text-fg-dim">
          <span aria-live="polite">Showing <span className="font-mono text-fg-muted">{rows.length}</span> most recent of <span className="font-mono text-fg-muted">{logs.length}</span> buffered</span>
          <Link to="/app/logs" className="font-medium text-fg-muted hover:text-signal">Open log explorer to search history</Link>
        </div>
        <div className={cx("max-h-[62vh] overflow-y-auto border-t border-[var(--hairline)] py-1.5")} role="log" aria-label="Live log events">
          {!hydrated ? <SkeletonRows rows={8} /> : rows.length === 0 ? (
            <EmptyState title={logs.length ? "No events match this filter" : "No events yet"} body={logs.length ? "Change the filter to see more." : "Log lines appear here as the tailer reads them."} className="py-16" />
          ) : rows.map((r) => <LogLine key={r.seq} record={r} />)}
        </div>
      </Panel>
    </div>
  );
}
