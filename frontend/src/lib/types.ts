/** Wire types for the HEALTH TRACE backend (backend/app/api, backend/app/models.py). */

export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type IncidentState = "OPEN" | "ACKNOWLEDGED" | "INVESTIGATING" | "RESOLVED";
export type AnomalyKind =
  | "error_rate"
  | "latency_degradation"
  | "hipaa_bulk_access"
  | "hipaa_off_hours"
  | "hipaa_region_mismatch"
  | "hipaa_bulk_export";

export interface WindowMetrics {
  service: string;
  window_end: string;
  total: number;
  errors: number;
  error_rate: number;
  p95_latency_ms: number;
  urgent_errors: number;
  affected_patients_urgent: number;
  affected_patients_routine: number;
  malformed_lines: number;
  /** The error-rate baseline this window was judged against (null while learning). */
  baseline_mean?: number | null;
  baseline_std?: number | null;
}

export interface ServiceState {
  service: string;
  window_end: string | null;
  total: number;
  errors: number;
  error_rate: number;
  p95_latency_ms: number;
  urgent_errors: number;
  baseline_mean: number | null;
  baseline_std: number | null;
  z: number | null;
  latency_baseline_mean: number | null;
  baseline_is_fallback: boolean;
  affected_patients_urgent: number;
  affected_patients_routine: number;
}

export interface ServiceRow extends ServiceState {
  criticality: number | null;
  label: string;
  depends_on: string[];
  active_incidents: number;
  worst_severity: Severity | null;
  baseline_ready: boolean;
  requests_per_second: number;
}

export interface Alert {
  id: number | null;
  ts: string;
  kind: AnomalyKind;
  service: string | null;
  user_id: string | null;
  severity: Severity;
  score: number;
  explanation: string;
  metrics: Record<string, number | string | null>;
  incident_id: number | null;
}

export interface Incident {
  id: number;
  fingerprint: string;
  kind: AnomalyKind;
  service: string | null;
  user_id: string | null;
  state: IncidentState;
  peak_severity: Severity;
  alert_count: number;
  opened_at: string;
  acknowledged_at: string | null;
  resolved_at: string | null;
  mttr_seconds: number | null;
  muted_until: string | null;
  pinned: boolean;
  pinned_at: string | null;
  investigating_at: string | null;
  /** Derived by the backend (incident_view). */
  title: string;
  source: string;
  status_label: string;
  severity: Severity;
  occurrence_count: number;
  first_seen_at: string;
  last_seen_at: string;
  /** The detector's own 0-100 score. null for rule-based (HIPAA) detections: never invented. */
  risk_score: number | null;
  risk_basis: string;
}

export type IncidentEventType =
  | "opened"
  | "alert_attached"
  | "escalated"
  | "acknowledged"
  | "investigating"
  | "resolved"
  | "auto_resolved"
  | "muted"
  | "pinned"
  | "unpinned";

export interface IncidentEvent {
  id: number | null;
  incident_id: number;
  ts: string;
  event_type: IncidentEventType;
  severity: Severity | null;
  detail: string | null;
}

export interface AppLogRecord {
  seq: number;
  ts: string;
  type: "app";
  service: string;
  level: "INFO" | "WARN" | "ERROR";
  priority: "urgent" | "routine";
  request_id: string;
  patient_id: string | null;
  status: number;
  latency_ms: number;
  msg: string;
  is_error: boolean;
}

export interface AuditLogRecord {
  seq: number;
  ts: string;
  type: "audit";
  user_id: string;
  role: string;
  action: string;
  patient_id: string;
  patient_region: string;
  user_region: string;
  region_mismatch: boolean;
  level: "INFO" | "WARN";
  msg: string;
}

export type LogRecord = AppLogRecord | AuditLogRecord;

export interface ThroughputSample {
  ts: string;
  app_eps: number;
  audit_eps: number;
}

export interface ReplayStatus {
  active: boolean;
  progress: number;
  event_clock: string | null;
  events_processed: number;
}

export interface Health {
  status: "ok" | "replaying";
  queue_depth: number;
  malformed_lines: number;
  aws_mode: "off" | "mock" | "live";
  notifier_queue_depth: number;
  demo_mode: boolean;
  started_at: string | null;
  uptime_seconds: number;
  event_clock: string | null;
  event_lag_seconds: number | null;
  events_processed: { app: number; audit: number };
  alerts_emitted: number;
  ws_clients: number;
  throughput: ThroughputSample | { app_eps: number; audit_eps: number };
  throughput_history: ThroughputSample[];
  replay: ReplayStatus;
  tailers: { path: string; offset: number; size: number; caught_up: boolean }[];
}

export interface Snapshot {
  type: "snapshot";
  services: ServiceRow[];
  alerts: Alert[];
  incidents: Incident[];
  metrics: Record<string, ServiceState>;
  health: Health;
  logs: LogRecord[];
}

export type LiveMessage =
  | Snapshot
  | ({ type: "metric" } & ServiceState & WindowMetrics)
  | ({ type: "alert" } & Alert)
  | ({ type: "incident_update"; incident: Incident } & IncidentEvent)
  | { type: "logs"; events: LogRecord[]; dropped: number }
  | ({ type: "replay" } & ReplayStatus)
  | { type: "heartbeat"; ts: string };

export interface EvidenceItem {
  id: number;
  alert_id: number | null;
  ts: string;
  record: Record<string, string | number | boolean | null>;
}

export interface IncidentSearchResult {
  items: Incident[];
  total: number;
  limit: number;
  offset: number;
  sort: string;
  order: string;
}

export interface IncidentSearchParams {
  status?: string;
  severity?: string;
  pinned?: boolean;
  since_hours?: number;
  q?: string;
  sort?: string;
  order?: "asc" | "desc";
  limit?: number;
  offset?: number;
}

export interface IncidentSummary {
  active: number;
  pinned: number;
  resolved: number;
  total: number;
  by_severity: Record<Severity, number>;
  by_status: Record<IncidentState, number>;
  unacknowledged_high: number;
  resolved_last_24h: number;
  mean_time_to_resolve_seconds: number | null;
  generated_at: string;
}

export interface ActivityItem {
  id: number;
  incident_id: number;
  ts: string;
  event_type: IncidentEventType;
  severity: Severity | null;
  detail: string | null;
  title: string;
}

export interface SystemStatus {
  backend: "ok";
  environment: string;
  database: { dialect: "sqlite" | "postgres"; ok: boolean; error: string | null; write_errors: number; last_write_error: string | null };
  stream: { state: "live" | "stale" | "replaying"; event_lag_seconds: number | null; ws_clients: number };
  data_source: "simulated" | "real";
  simulated_data: boolean;
  operator_auth: { required: boolean; configured: boolean };
  generated_at: string;
}

export interface NotificationAttempt {
  id: number;
  ts: string;
  channel: string;
  kind: string;
  provider: string;
  status: "accepted" | "failed" | "skipped";
  incident_id: number | null;
  severity: Severity | null;
  provider_message_id: string | null;
  detail: string | null;
}

export interface NotificationSettingsView {
  settings: {
    enabled: boolean;
    recipients: string[];
    min_severity: "HIGH" | "CRITICAL";
    cooldown_seconds: number;
    updated_at: string | null;
    updated_by: string | null;
  };
  provider: { name: "smtp" | "brevo"; configured: boolean; missing: string[]; sender: string | null; secret_configured: boolean };
  status: {
    sent: number;
    failed: number;
    skipped: number;
    retries: number;
    last_success_at: string | null;
    last_failure_at: string | null;
    last_error: string | null;
    queue_depth: number;
    sent_last_hour: number;
    max_per_hour: number;
    last_provider_message_id: string | null;
    delivery_confirmed: boolean;
    delivery_note: string;
    config_warnings: string[];
  };
  attempts: NotificationAttempt[];
  allowed_min_severities: ("HIGH" | "CRITICAL")[];
  warnings?: string[];
}

export interface NotificationSettingsInput {
  enabled: boolean;
  recipients: string[];
  min_severity: "HIGH" | "CRITICAL";
  cooldown_seconds: number;
}

export interface TestEmailResult {
  ok: boolean;
  result: "accepted_by_provider" | "failed";
  provider: string;
  provider_message_id: string | null;
  error: string | null;
  note: string | null;
}

export interface IncidentDetail {
  incident: Incident;
  events: IncidentEvent[];
  alerts: Alert[];
  evidence: EvidenceItem[];
  detection: DetectionRule;
}

export interface DetectionRule {
  metric: string;
  z_threshold?: number;
  min_errors?: number;
  min_rate?: number;
  min_std?: number;
  window_seconds?: number;
  step_seconds?: number;
  rolling_window_minutes?: number;
  severity?: SeverityConfig;
  hipaa?: HipaaConfig;
}

export interface SeverityConfig {
  deviation_z_cap: number;
  patient_factor_cap: number;
  criticality_weight: number;
  patient_factor_weight: number;
  thresholds: { low_max: number; medium_max: number; high_max: number };
}

export interface HipaaConfig {
  bulk_multiplier_high: number;
  bulk_multiplier_critical: number;
  bulk_min_threshold: number;
  export_min_threshold: number;
  export_critical_records: number;
  off_hours_start: string;
  off_hours_end: string;
  off_hours_high_records: number;
  region_mismatch_medium_max: number;
  timezone: string;
  realert_seconds: number;
}

export interface BaselineCell {
  hour_of_day: number;
  mean: number;
  std: number;
  count: number;
  ready: boolean;
}

export interface ServiceDetail extends ServiceRow {
  baselines: { error_rate: BaselineCell[]; p95_latency_ms: BaselineCell[] };
  incidents: Incident[];
  alerts: Alert[];
}

export interface LogSearchResult {
  events: LogRecord[];
  buffer_size: number;
  buffer_capacity: number;
}

export interface LogContext {
  event: LogRecord;
  before: LogRecord[];
  after: LogRecord[];
  related_alerts: Alert[];
}

export interface HipaaUser {
  user_id: string;
  distinct_patients: number;
  events: number;
  exports: number;
  off_hours_events: number;
  region_mismatch_patients: number;
  baseline: number | null;
  bulk_threshold: number;
  last_seen: string;
}

type SeverityCounts = Record<Severity, number>;

export interface Analytics {
  hours: number;
  since: string;
  alerts_per_hour: ({ hour: string } & SeverityCounts)[];
  alerts_by_service: Record<string, SeverityCounts>;
  alerts_by_kind: Record<string, number>;
  volume_per_hour: {
    hour: string;
    events: number;
    errors: number;
    error_rate: number;
    services: Record<string, { events: number; errors: number; error_rate: number; p95_latency_ms: number }>;
  }[];
  incidents: { total: number; active: number; resolved: number; by_severity: SeverityCounts };
  mttr_seconds: Record<string, { mean: number; count: number; max: number }>;
  recurring: { fingerprint: string; count: number }[];
  detection_lag_seconds: number | null;
}

export interface AppConfigResponse {
  detection: {
    services: Record<string, { criticality: number; label: string | null; depends_on: string[] }>;
    priority_weight: Record<string, number>;
    baseline: { alpha: number; warmup_windows: number };
    anomaly: {
      min_std: number;
      error_rate_z_threshold: number;
      error_rate_min_errors: number;
      error_rate_min_rate: number;
      latency_z_threshold: number;
      latency_min_std_ms: number;
    };
    severity: SeverityConfig;
    hipaa: HipaaConfig;
    incident: { cooldown_minutes: number; service_auto_resolve_windows: number; hipaa_auto_resolve_minutes: number };
    window: { size_seconds: number; step_seconds: number };
  };
  deployment: {
    project_name: string;
    environment: string;
    demo_mode: boolean;
    aws_mode: "off" | "mock" | "live";
    log_sources: { name: string; path: string; size_bytes: number; offset: number }[];
    operator_token_required: boolean;
  };
}

export interface ChannelStatus {
  sent: number;
  failed: number;
  skipped: number;
  retries: number;
  last_success_at: string | null;
  last_failure_at: string | null;
  last_error: string | null;
  recent: { ts: string; outcome: "sent" | "failed" | "skipped"; subject: string; error: string | null }[];
}

export type AwsIntegrationLabel = "MOCK" | "NOT CONFIGURED" | "CONFIGURED" | "ERROR";

export interface AwsStatus {
  integration: { status: AwsIntegrationLabel; verified: boolean; calls_aws: boolean; detail: string; problems?: string[] };
  requirement_note: string;
  mode: "off" | "mock" | "live";
  region: string;
  cloudwatch: { log_group: string; log_stream?: string } & ChannelStatus;
  sns: { topic_arn: string | null; configured: boolean } & ChannelStatus;
  queue_depth: number;
  config_warnings?: string[];
  credentials_source: string | null;
}

export interface EmailStatus extends ChannelStatus {
  enabled: boolean;
  provider?: "smtp" | "brevo";
  configured: boolean;
  missing: string[];
  host: string;
  port: number;
  use_tls: boolean;
  sender: string | null;
  recipients: string[];
  severities: string[];
  queue_depth: number;
  config_warnings: string[];
}

export interface AwsCheckResult {
  mode: string;
  cloudwatch: { ok: boolean; detail: string };
  sns: { ok: boolean; detail: string };
}

export interface DemoScenario {
  name: string;
  label: string;
  target: string | null;
  family: "service" | "hipaa" | "recovery";
  effect: string;
  expected: string;
}
