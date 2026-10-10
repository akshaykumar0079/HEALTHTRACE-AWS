import type {
  ActivityItem,
  Alert,
  Analytics,
  AppConfigResponse,
  AwsCheckResult,
  AwsStatus,
  EmailStatus,
  DemoScenario,
  Health,
  HipaaUser,
  Incident,
  IncidentDetail,
  IncidentSearchParams,
  IncidentSearchResult,
  IncidentSummary,
  NotificationSettingsInput,
  NotificationSettingsView,
  SystemStatus,
  TestEmailResult,
  LogContext,
  LogSearchResult,
  ServiceDetail,
  ServiceRow,
  WindowMetrics,
} from "./types";

const TOKEN_KEY = "healthtrace.operatorToken";

/**
 * Where the backend lives. Empty (the default) means same origin, which is
 * what `npm run dev` (proxy) and the single-container deployment use. For a
 * split deployment (frontend on Vercel, backend elsewhere) set
 * VITE_API_BASE_URL=https://<backend-host> at build time; no trailing slash.
 */
export const API_BASE: string = ((import.meta.env.VITE_API_BASE_URL as string | undefined) ?? "").replace(/\/+$/, "");

/** WebSocket endpoint: VITE_WS_URL if given, else derived from the API base, else this page's host. */
export function wsUrl(): string {
  const explicit = (import.meta.env.VITE_WS_URL as string | undefined)?.trim();
  if (explicit) return explicit;
  if (API_BASE) return API_BASE.replace(/^http/, "ws") + "/ws";
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${location.host}/ws`;
}

export function getOperatorToken(): string {
  try {
    return sessionStorage.getItem(TOKEN_KEY) ?? "";
  } catch {
    return "";
  }
}

export function setOperatorToken(token: string): void {
  try {
    if (token) sessionStorage.setItem(TOKEN_KEY, token);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    /* storage unavailable: token lives for this page only */
  }
}

export class ApiError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  if (init?.body) headers.set("Content-Type", "application/json");
  const token = getOperatorToken();
  if (token) headers.set("X-Operator-Token", token);

  let response: Response;
  try {
    response = await fetch(`${API_BASE}/api${path}`, { ...init, headers });
  } catch {
    throw new ApiError(0, "The HEALTHTRACE backend is unreachable.");
  }
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = (await response.json()) as { detail?: unknown };
      if (typeof body.detail === "string") detail = body.detail;
      else if (Array.isArray(body.detail)) detail = "The request was rejected as invalid.";
      else if (body.detail && typeof body.detail === "object" && "message" in body.detail) {
        const d = body.detail as { message: string; missing?: string[] };
        detail = d.missing?.length ? `${d.message} (missing: ${d.missing.join(", ")})` : d.message;
      }
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(response.status, detail);
  }
  return (await response.json()) as T;
}

const qs = (params: Record<string, string | number | undefined | null>) => {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") search.set(key, String(value));
  }
  const s = search.toString();
  return s ? `?${s}` : "";
};

export const api = {
  health: () => request<Health>("/health"),
  services: () => request<ServiceRow[]>("/services"),
  service: (name: string) => request<ServiceDetail>(`/services/${encodeURIComponent(name)}`),
  metrics: (service: string, minutes: number) =>
    request<WindowMetrics[]>(`/metrics${qs({ service, minutes })}`),
  alerts: (params: { limit?: number; severity?: string; service?: string; kind?: string; incident_id?: number } = {}) =>
    request<Alert[]>(`/alerts${qs(params)}`),
  incidents: (params: { state?: string; limit?: number } = {}) => request<Incident[]>(`/incidents${qs(params)}`),
  incident: (id: number) => request<IncidentDetail>(`/incidents/${id}`),
  incidentSearch: (params: IncidentSearchParams = {}) =>
    request<IncidentSearchResult>(`/incidents/search${qs({ ...params, pinned: params.pinned === undefined ? undefined : String(params.pinned) })}`),
  incidentSummary: () => request<IncidentSummary>("/incidents/summary"),
  activity: (limit = 12) => request<ActivityItem[]>(`/activity${qs({ limit })}`),
  status: () => request<SystemStatus>("/status"),
  investigate: (id: number) => request<Incident>(`/incidents/${id}/investigate`, { method: "POST" }),
  pin: (id: number) => request<Incident>(`/incidents/${id}/pin`, { method: "POST" }),
  unpin: (id: number) => request<Incident>(`/incidents/${id}/unpin`, { method: "POST" }),
  notificationSettings: () => request<NotificationSettingsView>("/settings/notifications"),
  saveNotificationSettings: (body: NotificationSettingsInput) =>
    request<NotificationSettingsView>("/settings/notifications", { method: "PUT", body: JSON.stringify(body) }),
  sendTestEmail: () => request<TestEmailResult>("/settings/notifications/test", { method: "POST" }),
  ack: (id: number) => request<Incident>(`/incidents/${id}/ack`, { method: "POST" }),
  resolve: (id: number) => request<Incident>(`/incidents/${id}/resolve`, { method: "POST" }),
  mute: (id: number, minutes: number) =>
    request<Incident>(`/incidents/${id}/mute`, { method: "POST", body: JSON.stringify({ minutes }) }),
  logs: (q: string, limit = 200) => request<LogSearchResult>(`/logs${qs({ q, limit })}`),
  logContext: (seq: number) => request<LogContext>(`/logs/${seq}/context`),
  hipaaUsers: () => request<HipaaUser[]>("/hipaa/users"),
  analytics: (hours: number) => request<Analytics>(`/analytics${qs({ hours })}`),
  config: () => request<AppConfigResponse>("/config"),
  awsStatus: () => request<AwsStatus>("/aws/status"),
  emailStatus: () => request<EmailStatus>("/notifications/email"),
  awsTestConnection: () => request<AwsCheckResult>("/aws/test-connection", { method: "POST" }),
  awsTestAlert: () => request<AwsCheckResult>("/aws/test-alert", { method: "POST" }),
  scenarios: () => request<{ enabled: boolean; scenarios: DemoScenario[] }>("/demo/scenarios"),
  inject: (scenario: string, duration_s: number) =>
    request<{ scenario: string; duration_s: number }>("/demo/inject", {
      method: "POST",
      body: JSON.stringify({ scenario, duration_s }),
    }),
};
