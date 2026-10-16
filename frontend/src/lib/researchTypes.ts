// Types for the user-provided dataset workflow (docs/user-datasets.md). Re-exported from ./types.

export type ResearchKind = "app" | "audit" | "auth";

export interface ResearchField {
  name: string;
  label: string;
  required: boolean;
  can_default?: boolean;
  values?: string[];
  default?: string;
  note?: string;
}

export interface ResearchMethod {
  id: string;
  title: string;
  description: string;
  kind: "pipeline" | "threshold";
  service_metric_only: boolean;
  sensitivity: boolean;
}

export interface ResearchInfo {
  enabled: boolean;
  warning: string;
  limits: { max_upload_mb: number; max_rows: number; max_columns: number; max_cell_chars: number };
  formats: string[];
  kinds: Record<ResearchKind, { fields: ResearchField[] }>;
  services: string[];
  methods: ResearchMethod[];
  default_methods: string[];
  retention_days: number;
  warmup_seconds: number;
  external_calls: 0;
}

export interface ResearchColumn {
  name: string;
  kind: "number" | "timestamp" | "text" | "empty";
  non_empty: number;
  distinct: number;
  sensitive_name: boolean;
  masked_in_preview: boolean;
}

export interface ResearchInspection {
  format: "csv" | "jsonl";
  delimiter: string | null;
  size_bytes: number;
  sha256: string;
  rows_parsed: number;
  rows_usable: number;
  rows_truncated_at_limit: boolean;
  row_rejects: Record<string, number>;
  columns: ResearchColumn[];
  sensitive_columns: string[];
  masked_columns: string[];
  preview_rows: Array<Record<string, string | number | null>>;
  distinct_values: Record<string, string[]>;
  preview_note: string;
}

export interface ResearchUploadResult {
  upload: { id: string; filename: string; format: string; size_bytes: number; uploaded_at: string };
  inspection: ResearchInspection;
}

export interface ResearchLabel {
  column: string;
  positive_values: string[];
  scope: "entity" | "dataset";
  merge_gap_seconds: number;
}

export interface ResearchMapping {
  kind: ResearchKind;
  columns: Record<string, string>;
  values: Record<string, Record<string, string>>;
  defaults: Record<string, string>;
  timezone: string;
  label: ResearchLabel | null;
}

export interface ResearchProblem {
  field: string;
  code: string;
  message: string;
}

export interface ResearchReport {
  ok: boolean;
  mode: "labeled" | "unlabeled";
  errors: ResearchProblem[];
  warnings: string[];
  rows?: {
    total: number;
    accepted: number;
    rejected: number;
    rejects_by_code: Record<string, number>;
    first_rows_by_code: Record<string, number[]>;
    explanations: Record<string, string>;
  };
  unmapped_values?: Record<string, string[]>;
  time_span?: { first: string | null; last: string | null; hours: number };
  events_by_entity?: Record<string, number>;
  labels?: { positive_rows: number; intervals: number; rows_missing_label: number };
}

export interface ResearchIncident {
  kind: string;
  entity: string;
  first_alert_at: string;
  last_alert_at: string | null;
  alerts: number;
  peak_severity: string | null;
}

export interface ResearchDelay {
  n: number;
  median: number | null;
  mean: number | null;
  min: number | null;
  max: number | null;
}

export interface ResearchMetrics {
  tp: number;
  fp: number;
  fn: number;
  duplicates: number;
  intervals: number;
  span_hours: number;
  precision: number | null;
  recall: number | null;
  f1: number | null;
  false_alarms_per_hour: number | null;
  delay_s: ResearchDelay;
}

export interface ResearchInterval {
  entity: string;
  start: string;
  end: string;
  labelled_rows: number;
  detected: boolean;
  delay_s: number | null;
  starts_in_detector_warmup: boolean;
}

export type ResearchEvaluation =
  | { mode: "descriptive"; metrics_measured: false; metrics: null; note: string }
  | {
      mode: "labeled";
      metrics_measured: true;
      metrics: ResearchMetrics;
      intervals: ResearchInterval[];
      false_alarms: Array<Omit<ResearchIncident, "last_alert_at" | "alerts">>;
      assumptions: string[];
    };

export interface ResearchMethodResult {
  method: string;
  applicable: boolean;
  reason?: string;
  incidents_found?: number;
  incidents?: ResearchIncident[];
  incidents_truncated?: boolean;
  by_severity?: Record<string, number>;
  evaluation?: ResearchEvaluation;
}

export interface ResearchExperiment {
  id: string;
  created_at: string;
  created_by: string;
  upload: { sha256: string; filename: string; format: string; size_bytes: number };
  config: { mapping: ResearchMapping; mode: "labeled" | "descriptive"; methods: string[]; upload_sha256: string };
  result: {
    dataset: {
      kind: ResearchKind;
      rows_total: number;
      rows_accepted: number;
      rows_rejected: number;
      first_event_at: string | null;
      last_event_at: string | null;
      span_hours: number;
      detector_warmup_seconds: number;
      warnings: string[];
    };
    methods: ResearchMethodResult[];
  };
  results_sha256: string;
  rerun_of?: string;
  reproduced?: boolean;
  disclaimer: string;
}

export interface ResearchExperimentRow {
  id: string;
  created_at: string;
  filename: string;
  mode: string;
  kind: ResearchKind;
  methods: string[];
  results_sha256: string;
  rerun_of: string | null;
  reproduced: boolean | null;
  incidents_found: Record<string, number | undefined>;
}

export interface ResearchComparison {
  a: { id: string; mode: string; methods: string[]; filename: string };
  b: { id: string; mode: string; methods: string[]; filename: string };
  same_upload: boolean;
  same_mapping: boolean;
  same_methods: boolean;
  same_detector_config: boolean;
  results_identical: boolean;
  rows: Array<{ method: string; metric: string; a: number | null; b: number | null }>;
  note: string;
}
