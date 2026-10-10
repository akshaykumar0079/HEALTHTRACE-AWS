import { useQuery } from "@tanstack/react-query";
import { Database, Flask, Plugs, Pulse } from "@phosphor-icons/react";
import { api } from "@/lib/api";
import { dataFreshness, reconnectNow, useLive, type DataFreshness } from "@/lib/live";
import { Beacon, cx } from "./ui";

const FRESHNESS: Record<DataFreshness, { label: string; color: string; detail: string }> = {
  live: { label: "Live", color: "#56dcc8", detail: "Events are flowing" },
  stale: { label: "Stale", color: "#e3b35a", detail: "Connected, but no recent log events are arriving" },
  replaying: { label: "Catching up", color: "#e3b35a", detail: "Processing earlier log history" },
  connecting: { label: "Connecting", color: "#627085", detail: "Opening the live connection" },
  disconnected: { label: "Disconnected", color: "#f05a73", detail: "The live connection is down; data may be out of date" },
};

export function useFreshness(): DataFreshness {
  const connection = useLive((s) => s.connection);
  const health = useLive((s) => s.health);
  const replaying = useLive((s) => !!s.replay?.active);
  return dataFreshness(connection, health, replaying);
}

/** Simulated-data marker. The source is synthetic by default, so this is shown prominently, not hidden. */
export function SimulatedBadge({ className }: { className?: string }) {
  const { data } = useQuery({ queryKey: ["status"], queryFn: api.status, staleTime: 30_000 });
  if (!data?.simulated_data) return null;
  return (
    <span
      className={cx("inline-flex h-7 items-center gap-1.5 rounded-full bg-[#e3b35a14] px-2.5 text-[11px] font-medium tracking-wide text-sev-medium shadow-[inset_0_0_0_1px_rgb(227_179_90/0.35)]", className)}
      title="This deployment is fed by the synthetic log generator. No real patient data is involved."
    >
      <Flask size={13} />
      SIMULATED<span className="max-sm:hidden"> DATA</span>
    </span>
  );
}

function Item({ icon, label, value, color, title }: { icon: React.ReactNode; label: string; value: string; color: string; title?: string }) {
  return (
    <div className="flex items-center gap-2.5 px-4 py-2.5" title={title}>
      <span className="text-fg-dim" aria-hidden>{icon}</span>
      <div className="min-w-0">
        <p className="text-[11px] text-fg-dim">{label}</p>
        <p className="flex items-center gap-1.5 text-[12.5px] font-medium text-fg">
          <Beacon color={color} pulse={false} size={7} /> {value}
        </p>
      </div>
    </div>
  );
}

/** Backend / database / live-stream status, from real endpoints. Each item has a text value, not just a colour. */
export function StatusStrip() {
  const connection = useLive((s) => s.connection);
  const freshness = useFreshness();
  const lag = useLive((s) => s.health?.event_lag_seconds ?? null);
  const { data, isError } = useQuery({ queryKey: ["status"], queryFn: api.status, refetchInterval: 15_000 });
  const f = FRESHNESS[freshness];
  const backendOk = !isError && !!data;
  const db = data?.database;
  return (
    <div className="panel flex flex-wrap items-stretch divide-x divide-[var(--hairline)] overflow-hidden" role="status" aria-label="System status">
      <Item icon={<Plugs size={16} />} label="Backend" value={backendOk ? "Reachable" : isError ? "Unreachable" : "Checking"} color={backendOk ? "#56dcc8" : isError ? "#f05a73" : "#627085"} />
      <Item
        icon={<Database size={16} />}
        label="Database"
        value={db ? `${db.dialect === "postgres" ? "PostgreSQL" : "SQLite"}${db.ok ? "" : " (error)"}` : "Checking"}
        color={db ? (db.ok && db.write_errors === 0 ? "#56dcc8" : "#e3b35a") : "#627085"}
        title={db?.last_write_error ? `Last write problem: ${db.last_write_error}` : undefined}
      />
      <Item
        icon={<Pulse size={16} />}
        label="Live stream"
        value={`${f.label}${freshness === "live" && lag != null ? ` (${Math.max(0, Math.round(lag))}s behind)` : ""}`}
        color={f.color}
        title={f.detail}
      />
      <div className="flex items-center gap-3 px-4 py-2.5">
        <span className="text-[11.5px] text-fg-dim">{f.detail}</span>
        {connection !== "live" && (
          <button onClick={reconnectNow} className="rounded-md bg-ink-750 px-2.5 py-1 text-[12px] font-medium text-fg hover:bg-ink-700">
            Retry now
          </button>
        )}
      </div>
    </div>
  );
}
