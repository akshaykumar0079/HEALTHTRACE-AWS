import type { ResearchField, ResearchKind, ResearchLabel, ResearchMapping } from "./types";

const SYNONYMS: Record<string, string[]> = {
  ts: ["ts", "timestamp", "time", "datetime", "date", "eventtime", "createdat", "atttimestamp", "timestamputc"],
  service: ["service", "component", "app", "application", "system", "module", "servicename"],
  level: ["level", "severity", "loglevel", "sev"],
  status: ["status", "statuscode", "http", "httpstatus", "responsecode", "code"],
  latency_ms: ["latencyms", "latency", "durationms", "duration", "responsetime", "elapsedms", "ms"],
  priority: ["priority", "urgency", "prio"],
  patient_id: ["patientid", "patient", "patientref", "mrn", "memberid"],
  request_id: ["requestid", "reqid", "traceid", "correlationid", "id"],
  user_id: ["userid", "user", "username", "actor", "who", "staffid"],
  action: ["action", "operation", "activity", "event", "what"],
  outcome: ["outcome", "result", "loginresult"],
  role: ["role", "userrole"],
  patient_region: ["patientregion", "facilityregion"],
  user_region: ["userregion", "homeregion"],
  source_region: ["sourceregion", "loginregion", "region"],
  source_ip: ["sourceip", "clientip", "ip", "ipaddress"],
  method: ["method", "authmethod"],
};

const norm = (s: string) => s.toLowerCase().replace(/[^a-z0-9]/g, "");

/** Best-guess column for each detector field, by common column names. Each column is used at most once. */
export function suggestMapping(columns: string[], fields: ResearchField[]): Record<string, string> {
  const out: Record<string, string> = {};
  const used = new Set<string>();
  for (const f of fields) {
    const wanted = new Set([norm(f.name), ...(SYNONYMS[f.name] ?? [])]);
    const hit = columns.find((c) => !used.has(c) && wanted.has(norm(c)));
    if (hit) {
      out[f.name] = hit;
      used.add(hit);
    }
  }
  return out;
}

export interface MappingDraft {
  kind: ResearchKind;
  columns: Record<string, string>;
  defaults: Record<string, string>;
  /** field -> source value -> canonical value; "" or "auto" means 'let the server interpret it' */
  values: Record<string, Record<string, string>>;
  timezone: string;
  label: { enabled: boolean; column: string; positives: string[]; scope: ResearchLabel["scope"]; gap: number };
}

/** The payload the server validates. Empty choices are dropped; nothing here is trusted by the server. */
export function buildMapping(d: MappingDraft): ResearchMapping {
  const columns = Object.fromEntries(Object.entries(d.columns).filter(([, v]) => v));
  const defaults = Object.fromEntries(Object.entries(d.defaults).filter(([f, v]) => v && !columns[f]));
  const values: Record<string, Record<string, string>> = {};
  for (const [field, map] of Object.entries(d.values)) {
    if (!columns[field]) continue;
    const kept = Object.fromEntries(Object.entries(map).filter(([, v]) => v && v !== "auto"));
    if (Object.keys(kept).length) values[field] = kept;
  }
  const l = d.label;
  const label: ResearchLabel | null =
    l.enabled && l.column && l.positives.length
      ? { column: l.column, positive_values: l.positives, scope: l.scope, merge_gap_seconds: l.gap }
      : null;
  return { kind: d.kind, columns, values, defaults, timezone: d.timezone || "UTC", label };
}

export function emptyDraft(kind: ResearchKind, columns: string[], fields: ResearchField[]): MappingDraft {
  return {
    kind,
    columns: suggestMapping(columns, fields),
    defaults: {},
    values: {},
    timezone: "UTC",
    label: { enabled: false, column: "", positives: [], scope: "entity", gap: 60 },
  };
}

export const pct = (v: number | null | undefined): string => (v == null ? "n/a" : `${(v * 100).toFixed(0)}%`);
export const num = (v: number | null | undefined, digits = 2): string => (v == null ? "n/a" : String(Number(v.toFixed(digits))));
export const seconds = (v: number | null | undefined): string => (v == null ? "n/a" : `${num(v, 1)} s`);

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

/** Client-side pre-check so an obviously wrong file is refused before it is sent. The server checks again. */
export function precheckFile(file: { name: string; size: number }, formats: string[], maxMb: number): string | null {
  const dot = file.name.lastIndexOf(".");
  const ext = dot >= 0 ? file.name.slice(dot).toLowerCase() : "";
  if (!formats.includes(ext)) return `Unsupported file type ${ext || "(none)"}. Use ${formats.join(", ")}.`;
  if (file.size === 0) return "The file is empty.";
  if (file.size > maxMb * 1024 * 1024) return `The file is larger than the ${maxMb} MB limit.`;
  return null;
}
