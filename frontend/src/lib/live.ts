import { create } from "zustand";
import { api, wsUrl } from "./api";
import type {
  Alert,
  Health,
  Incident,
  LiveMessage,
  LogRecord,
  ReplayStatus,
  ServiceRow,
  Severity,
  WindowMetrics,
} from "./types";
import { SEVERITY_ORDER } from "./format";

export type ConnectionState = "connecting" | "live" | "reconnecting" | "offline";

export interface SeriesPoint {
  t: number;
  rate: number;
  errors: number;
  total: number;
  p95: number;
  mean: number | null;
  std: number | null;
}

export interface Pulse {
  id: number;
  service: string | null;
  severity: Severity;
  at: number;
}

const SERIES_CAP = 17280; // 24h of 5s windows per service
const ALERT_CAP = 400;
const LOG_CAP = 600;
const PAUSED_CAP = 600; // events held back while the feed is paused; oldest are dropped past this
const HISTORY_MINUTES = 60;

interface LiveState {
  connection: ConnectionState;
  attempts: number;
  lastMessageAt: number | null;
  hydrated: boolean;
  services: Record<string, ServiceRow>;
  series: Record<string, SeriesPoint[]>;
  alerts: Alert[];
  freshAlertIds: Set<number>;
  incidents: Record<number, Incident>;
  logs: LogRecord[];
  logsPaused: boolean;
  /** Events that arrived while paused (newest first), shown as "N new events" and flushed on resume. */
  pausedBuffer: LogRecord[];
  pausedDropped: number;
  /** Bumped on every incident_update so list pages can refresh without polling. */
  incidentVersion: number;
  health: Health | null;
  replay: ReplayStatus | null;
  pulses: Pulse[];
  setLogsPaused: (paused: boolean) => void;
  upsertIncident: (incident: Incident) => void;
}

export const useLive = create<LiveState>((set) => ({
  connection: "connecting",
  attempts: 0,
  lastMessageAt: null,
  hydrated: false,
  services: {},
  series: {},
  alerts: [],
  freshAlertIds: new Set(),
  incidents: {},
  logs: [],
  logsPaused: false,
  pausedBuffer: [],
  pausedDropped: 0,
  incidentVersion: 0,
  health: null,
  replay: null,
  pulses: [],
  setLogsPaused: (paused) =>
    set((s) => {
      if (paused) return { logsPaused: true };
      // Resume: merge what was held back so nothing is lost, then clear the buffer.
      const logs = [...s.pausedBuffer, ...s.logs].slice(0, LOG_CAP);
      return { logsPaused: false, logs, pausedBuffer: [], pausedDropped: 0 };
    }),
  upsertIncident: (incident) => set((s) => ({ incidents: { ...s.incidents, [incident.id]: incident } })),
}));

const toPoint = (m: WindowMetrics): SeriesPoint => ({
  t: new Date(m.window_end).getTime(),
  rate: m.error_rate,
  errors: m.errors,
  total: m.total,
  p95: m.p95_latency_ms,
  mean: m.baseline_mean ?? null,
  std: m.baseline_std ?? null,
});

function appendPoint(series: SeriesPoint[] | undefined, point: SeriesPoint): SeriesPoint[] {
  const list = series ? series.slice() : [];
  const last = list[list.length - 1];
  if (last && point.t <= last.t) {
    if (point.t === last.t) list[list.length - 1] = point;
    return list;
  }
  list.push(point);
  if (list.length > SERIES_CAP) list.splice(0, list.length - SERIES_CAP);
  return list;
}

let pulseSeq = 0;
const FRESH_MS = 6000;

function handle(message: LiveMessage): void {
  const now = Date.now();
  switch (message.type) {
    case "snapshot": {
      const services: Record<string, ServiceRow> = {};
      for (const row of message.services) services[row.service] = row;
      const incidents: Record<number, Incident> = {};
      for (const inc of message.incidents) incidents[inc.id] = inc;
      useLive.setState({
        services,
        incidents,
        alerts: message.alerts.slice().reverse().slice(0, ALERT_CAP),
        logs: message.logs.slice().reverse().slice(0, LOG_CAP),
        health: message.health,
        replay: message.health.replay,
        hydrated: true,
      });
      void loadHistory(Object.keys(services));
      return;
    }
    case "metric": {
      useLive.setState((s) => {
        const prev = s.services[message.service];
        const row: ServiceRow = prev
          ? { ...prev, ...pickState(message) }
          : ({ ...pickState(message), label: message.service, depends_on: [], criticality: null,
               active_incidents: 0, worst_severity: null, baseline_ready: message.baseline_mean !== null,
               requests_per_second: message.total / 60 } as ServiceRow);
        row.baseline_ready = message.baseline_mean !== null;
        row.requests_per_second = message.total / 60;
        return {
          services: { ...s.services, [message.service]: row },
          series: { ...s.series, [message.service]: appendPoint(s.series[message.service], toPoint(message)) },
        };
      });
      return;
    }
    case "alert": {
      const { type: _type, ...alert } = message;
      useLive.setState((s) => {
        const fresh = new Set(s.freshAlertIds);
        if (alert.id != null) fresh.add(alert.id);
        const pulses = [...s.pulses.filter((p) => now - p.at < 8000),
          { id: ++pulseSeq, service: alert.service, severity: alert.severity, at: now }];
        return { alerts: [alert, ...s.alerts].slice(0, ALERT_CAP), freshAlertIds: fresh, pulses };
      });
      if (alert.id != null) {
        const id = alert.id;
        window.setTimeout(() => {
          useLive.setState((s) => {
            const fresh = new Set(s.freshAlertIds);
            fresh.delete(id);
            return { freshAlertIds: fresh };
          });
        }, FRESH_MS);
      }
      return;
    }
    case "incident_update": {
      useLive.setState((s) => {
        const incidents = { ...s.incidents, [message.incident.id]: message.incident };
        return {
          incidents,
          services: recomputeServiceIncidents(s.services, incidents),
          incidentVersion: s.incidentVersion + 1,
        };
      });
      return;
    }
    case "logs": {
      // A batch can overlap the tail already delivered in a snapshot.
      useLive.setState((s) => {
        const newest = s.pausedBuffer[0]?.seq ?? s.logs[0]?.seq ?? 0;
        const fresh = message.events.filter((e) => e.seq > newest).reverse();
        if (!fresh.length) return {};
        if (s.logsPaused) {
          // Paused: hold events back (bounded) instead of dropping them.
          const merged = [...fresh, ...s.pausedBuffer];
          const dropped = Math.max(0, merged.length - PAUSED_CAP);
          return { pausedBuffer: merged.slice(0, PAUSED_CAP), pausedDropped: s.pausedDropped + dropped };
        }
        return { logs: [...fresh, ...s.logs].slice(0, LOG_CAP) };
      });
      return;
    }
    case "replay": {
      const { type: _type, ...replay } = message;
      useLive.setState({ replay });
      return;
    }
    case "heartbeat":
      return;
  }
}

function pickState(m: LiveMessage & { type: "metric" }) {
  return {
    service: m.service,
    window_end: m.window_end,
    total: m.total,
    errors: m.errors,
    error_rate: m.error_rate,
    p95_latency_ms: m.p95_latency_ms,
    urgent_errors: m.urgent_errors,
    baseline_mean: m.baseline_mean,
    baseline_std: m.baseline_std,
    z: m.z,
    latency_baseline_mean: m.latency_baseline_mean,
    baseline_is_fallback: m.baseline_is_fallback,
    affected_patients_urgent: m.affected_patients_urgent,
    affected_patients_routine: m.affected_patients_routine,
  };
}

function recomputeServiceIncidents(
  services: Record<string, ServiceRow>,
  incidents: Record<number, Incident>,
): Record<string, ServiceRow> {
  const next: Record<string, ServiceRow> = {};
  const active = Object.values(incidents).filter((i) => i.state !== "RESOLVED" && i.service);
  for (const [name, row] of Object.entries(services)) {
    const mine = active.filter((i) => i.service === name);
    const worst = mine.reduce<Severity | null>(
      (acc, i) => (acc === null || SEVERITY_ORDER[i.peak_severity] > SEVERITY_ORDER[acc] ? i.peak_severity : acc),
      null,
    );
    next[name] = { ...row, active_incidents: mine.length, worst_severity: worst };
  }
  return next;
}

async function loadHistory(services: string[]): Promise<void> {
  const results = await Promise.allSettled(services.map((s) => api.metrics(s, HISTORY_MINUTES)));
  useLive.setState((state) => {
    const series = { ...state.series };
    results.forEach((result, i) => {
      if (result.status !== "fulfilled") return;
      const history = result.value.map(toPoint);
      const live = state.series[services[i]] ?? [];
      const cutoff = history.length ? history[history.length - 1].t : 0;
      series[services[i]] = [...history, ...live.filter((p) => p.t > cutoff)].slice(-SERIES_CAP);
    });
    return { series };
  });
}

/** Health (throughput, lag) is not pushed over the socket; poll it lightly. */
async function refreshHealth(): Promise<void> {
  try {
    const health = await api.health();
    useLive.setState({ health, replay: health.replay });
  } catch {
    /* connection state already reflects outages */
  }
}

// -- socket lifecycle ---------------------------------------------------------

let socket: WebSocket | null = null;
let retryTimer: number | undefined;
let watchdog: number | undefined;
let healthTimer: number | undefined;
let started = false;
const WATCHDOG_MS = 25000;
export const STALE_AFTER_SECONDS = 30;

function armWatchdog(): void {
  window.clearTimeout(watchdog);
  watchdog = window.setTimeout(() => socket?.close(4000, "heartbeat timeout"), WATCHDOG_MS);
}

function connect(): void {
  window.clearTimeout(retryTimer);
  const ws = new WebSocket(wsUrl());
  socket = ws;
  ws.onopen = () => {
    useLive.setState({ connection: "live", attempts: 0 });
    armWatchdog();
  };
  ws.onmessage = (event) => {
    if (socket !== ws) return; // a superseded socket must not write state (no duplicate subscriptions)
    armWatchdog();
    useLive.setState({ lastMessageAt: Date.now() });
    try {
      handle(JSON.parse(event.data as string) as LiveMessage);
    } catch (err) {
      console.error("health-trace: bad live message", err);
    }
  };
  ws.onclose = () => {
    window.clearTimeout(watchdog);
    if (socket !== ws) return;
    socket = null;
    const attempts = useLive.getState().attempts + 1;
    useLive.setState({ connection: attempts > 8 ? "offline" : "reconnecting", attempts });
    const delay = Math.min(10000, 500 * 2 ** Math.min(attempts, 5)) * (0.75 + Math.random() * 0.5);
    retryTimer = window.setTimeout(connect, delay);
  };
  ws.onerror = () => ws.close();
}

export function startLive(): void {
  if (started) return;
  started = true;
  connect();
  void refreshHealth();
  healthTimer = window.setInterval(refreshHealth, 2000);
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible" && !socket) connect();
  });
  window.addEventListener("online", () => {
    if (!socket) connect();
  });
}

export function reconnectNow(): void {
  useLive.setState({ attempts: 0, connection: "connecting" });
  if (socket) socket.close();
  else connect();
}

export function stopLive(): void {
  started = false;
  window.clearInterval(healthTimer);
  window.clearTimeout(retryTimer);
  window.clearTimeout(watchdog);
  const ws = socket;
  socket = null;
  ws?.close();
}

// -- selectors ------------------------------------------------------------------

export const activeIncidents = (incidents: Record<number, Incident>) =>
  Object.values(incidents)
    .filter((i) => i.state !== "RESOLVED")
    .sort(
      (a, b) =>
        SEVERITY_ORDER[b.peak_severity] - SEVERITY_ORDER[a.peak_severity] ||
        (b.risk_score ?? -1) - (a.risk_score ?? -1) ||
        b.last_seen_at.localeCompare(a.last_seen_at),
    );

export type DataFreshness = "live" | "stale" | "replaying" | "disconnected" | "connecting";

/**
 * "Live" means events are actually flowing, not just that the socket is open:
 * a connected socket whose log source has gone quiet is "stale".
 */
export function dataFreshness(connection: ConnectionState, health: Health | null, replaying: boolean): DataFreshness {
  if (connection === "connecting") return "connecting";
  if (connection !== "live") return "disconnected";
  if (replaying) return "replaying";
  const lag = health?.event_lag_seconds;
  return lag == null || lag > STALE_AFTER_SECONDS ? "stale" : "live";
}

export function systemSeverity(incidents: Record<number, Incident>): Severity | null {
  return activeIncidents(incidents)[0]?.peak_severity ?? null;
}

/** Fleet-wide error rate from the latest window of every service. */
export function fleetRate(services: Record<string, ServiceRow>): { rate: number; baseline: number | null; total: number } {
  let total = 0;
  let errors = 0;
  let expected = 0;
  let covered = 0;
  for (const row of Object.values(services)) {
    total += row.total;
    errors += row.errors;
    if (row.baseline_mean !== null) {
      expected += row.baseline_mean * row.total;
      covered += row.total;
    }
  }
  return { rate: total ? errors / total : 0, baseline: covered ? expected / covered : null, total };
}
