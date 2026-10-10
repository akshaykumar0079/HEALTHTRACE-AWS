import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { keepPreviousData, useQuery, useQueryClient } from "@tanstack/react-query";
import { MagnifyingGlass, PushPin, ShieldCheck, WifiSlash } from "@phosphor-icons/react";
import { api, getOperatorToken } from "@/lib/api";
import { useLive } from "@/lib/live";
import type { Incident, IncidentSearchParams, Severity } from "@/lib/types";
import { SEVERITIES, STATES, STATE_LABEL, SEVERITY_HEX, ago, stamp } from "@/lib/format";
import { EmptyState, ErrorState, Panel, SeverityBadge, SkeletonRows, StateBadge, cx, inputClass } from "./ui";
import { IncidentActions, PinButton } from "./domain";

export type IncidentPreset = "active" | "pinned" | "history" | "all";

const ACTIVE_STATES = "OPEN,ACKNOWLEDGED,INVESTIGATING";
const PAGE = 50;

const SORT_OPTIONS: [string, string][] = [
  ["priority", "Priority (severity, risk, recency)"],
  ["recent", "Most recently seen"],
  ["opened", "First seen"],
  ["severity", "Severity"],
  ["risk", "Risk score"],
  ["occurrences", "Occurrences"],
];

const HISTORY_WINDOWS: [string, string][] = [
  ["", "All time"],
  ["24", "Last 24 hours"],
  ["168", "Last 7 days"],
  ["720", "Last 30 days"],
];

const EMPTY_COPY: Record<IncidentPreset, { title: string; body: string }> = {
  active: { title: "No active incidents", body: "Nothing needs attention. New incidents appear here the moment detection opens one." },
  pinned: { title: "Nothing pinned", body: "Pin an incident from the Incidents list to keep it here. Pinning never changes its severity or status." },
  history: { title: "No resolved incidents", body: "Resolved incidents stay here, with their evidence and timeline, so they remain searchable." },
  all: { title: "No incidents", body: "No incident matches these filters." },
};

/** Risk score: the detector's own number, or an explicit dash with the reason. Never a made-up value. */
export function RiskScore({ incident }: { incident: Incident }) {
  if (incident.risk_score === null) {
    return (
      <span className="text-fg-dim" title={`No score: ${incident.risk_basis}`}>
        <span aria-hidden>-</span>
        <span className="sr-only">No risk score, rule-based detection</span>
      </span>
    );
  }
  return (
    <span className="font-mono tabular text-fg" title={`Risk score ${incident.risk_score} of 100 (${incident.risk_basis})`}>
      {incident.risk_score}
      <span className="text-fg-dim">/100</span>
    </span>
  );
}

const TREND_META = {
  rising: { symbol: "↗", label: "Risk rising", color: "var(--color-sev-high)" },
  falling: { symbol: "↘", label: "Risk falling", color: "var(--color-signal)" },
  stable: { symbol: "→", label: "Risk stable", color: "var(--color-fg-muted)" },
  unknown: { symbol: "·", label: "Trend unknown", color: "var(--color-fg-dim)" },
} as const;

/** Direction of recent risk. Text and an arrow, never colour alone. Trend is not severity. */
export function TrendChip({ incident }: { incident: Incident }) {
  const t = TREND_META[incident.risk_trend ?? "unknown"];
  return (
    <span className="inline-flex items-center gap-1 text-[12px]" style={{ color: t.color }} title={incident.risk_trend_basis ? `Based on ${incident.risk_trend_basis}` : undefined}>
      <span aria-hidden>{t.symbol}</span>
      <span>{t.label}</span>
    </span>
  );
}

const QUALITY_LABEL = { none: "No evidence", limited: "Limited evidence", moderate: "Moderate evidence", strong: "Strong evidence" } as const;

/** How much stored evidence backs the incident. Separate from severity and risk score. */
export function EvidenceQualityChip({ quality, count }: { quality?: Incident["evidence_quality"]; count?: number }) {
  const q = quality ?? "none";
  return (
    <span className="text-[12px] text-fg-muted" title="Evidence quality counts the stored log records; it is not severity or risk.">
      {QUALITY_LABEL[q]}{count ? ` (${count})` : ""}
    </span>
  );
}

function useDebounced<T>(value: T, ms: number): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = window.setTimeout(() => setV(value), ms);
    return () => window.clearTimeout(t);
  }, [value, ms]);
  return v;
}

/** Refresh incident lists when the live socket reports a change (debounced, no polling). */
export function useLiveIncidentRefresh() {
  const qc = useQueryClient();
  const version = useLive((s) => s.incidentVersion);
  useEffect(() => {
    if (version === 0) return;
    const t = window.setTimeout(() => {
      void qc.invalidateQueries({ queryKey: ["incidents"] });
      void qc.invalidateQueries({ queryKey: ["incident-summary"] });
      void qc.invalidateQueries({ queryKey: ["activity"] });
    }, 600);
    return () => window.clearTimeout(t);
  }, [version, qc]);
}

export function OperatorNotice() {
  const { data } = useQuery({ queryKey: ["status"], queryFn: api.status, staleTime: 30_000 });
  const token = getOperatorToken();
  if (!data) return null;
  const a = data.operator_auth;
  if (a.required && !a.configured) {
    return (
      <p role="status" className="flex items-center gap-2 rounded-[12px] bg-ink-850 px-4 py-2.5 text-[12.5px] text-fg-muted shadow-[inset_0_0_0_1px_var(--hairline)]">
        <ShieldCheck size={16} className="shrink-0 text-sev-medium" />
        Actions are disabled: this server requires an operator token but none is configured (set OPERATOR_TOKEN). You can view everything.
      </p>
    );
  }
  if ((a.required || a.configured) && !token) {
    return (
      <p role="status" className="flex items-center gap-2 rounded-[12px] bg-ink-850 px-4 py-2.5 text-[12.5px] text-fg-muted shadow-[inset_0_0_0_1px_var(--hairline)]">
        <ShieldCheck size={16} className="shrink-0 text-sev-medium" />
        Read-only view. To pin, acknowledge or resolve, enter the operator token in
        <Link to="/app/settings#access" className="text-signal hover:underline">Settings, API access</Link>.
      </p>
    );
  }
  return null;
}

export function IncidentTable({ preset }: { preset: IncidentPreset }) {
  const [params, setParams] = useSearchParams();
  const connection = useLive((s) => s.connection);
  const [limit, setLimit] = useState(PAGE);
  const setParam = (key: string, value: string | null) => {
    setParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        if (value) next.set(key, value);
        else next.delete(key);
        return next;
      },
      { replace: true },
    );
    setLimit(PAGE);
  };

  const q = params.get("q") ?? "";
  const [qInput, setQInput] = useState(q);
  const debouncedQ = useDebounced(qInput, 300);
  useEffect(() => {
    if (debouncedQ !== q) setParam("q", debouncedQ.trim() || null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debouncedQ]);

  const severities = (params.get("severity") ?? "").split(",").filter(Boolean) as Severity[];
  const statuses = (params.get("status") ?? "").split(",").filter(Boolean);
  const sort = params.get("sort") ?? "priority";
  const pinnedOnly = preset === "pinned" || params.get("pinned") === "1";
  const within = params.get("within") ?? "";
  const service = params.get("service") ?? "";
  const source = (params.get("source") ?? "") as "" | "app" | "audit" | "auth";
  const config = useQuery({ queryKey: ["config"], queryFn: api.config, staleTime: 60_000 });
  const serviceNames = Object.keys(config.data?.detection.services ?? {});

  const query: IncidentSearchParams = useMemo(() => {
    const base: IncidentSearchParams = { q: q || undefined, sort, limit, severity: severities.join(",") || undefined, service: service || undefined, source: source || undefined };
    if (preset !== "history" && within) base.since_hours = Number(within);
    if (preset === "history") {
      base.status = "RESOLVED";
      if (within) base.since_hours = Number(within);
      base.sort = sort === "priority" ? "recent" : sort;
    } else if (preset === "pinned") {
      base.pinned = true;
      base.status = statuses.join(",") || undefined;
    } else {
      base.status = statuses.join(",") || (preset === "active" ? ACTIVE_STATES : undefined);
      if (pinnedOnly) base.pinned = true;
    }
    return base;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [preset, q, sort, limit, params, within, service, source]);

  useLiveIncidentRefresh();
  const { data, error, isLoading, isFetching, refetch } = useQuery({
    queryKey: ["incidents", query],
    queryFn: () => api.incidentSearch(query),
    placeholderData: keepPreviousData,
  });

  const toggle = (key: "severity" | "status", value: string, current: string[]) =>
    setParam(key, (current.includes(value) ? current.filter((v) => v !== value) : [...current, value]).join(",") || null);

  const filtered = !!(q || severities.length || statuses.length || within || service || source || (preset !== "pinned" && pinnedOnly));
  const statusChoices = preset === "active" ? STATES.filter((s) => s !== "RESOLVED") : STATES;

  return (
    <div className="space-y-4">
      <OperatorNotice />
      {connection !== "live" && (
        <p role="status" className="flex items-center gap-2 rounded-[12px] bg-[#e3b35a0d] px-4 py-2.5 text-[12.5px] text-fg-muted shadow-[inset_0_0_0_1px_rgb(227_179_90/0.25)]">
          <WifiSlash size={16} className="shrink-0 text-sev-medium" />
          Live updates are {connection === "offline" ? "offline" : "reconnecting"}. The list below is the last data loaded and may be out of date.
        </p>
      )}

      <Panel>
        <div className="flex flex-wrap items-end gap-x-5 gap-y-3 p-4">
          <div className="min-w-[220px] flex-1">
            <label htmlFor="incident-search" className="mb-1.5 block text-[11.5px] text-fg-dim">Search</label>
            <div className="relative">
              <MagnifyingGlass size={15} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-fg-dim" />
              <input
                id="incident-search"
                type="search"
                value={qInput}
                onChange={(e) => setQInput(e.target.value)}
                placeholder="Title, source, user, or #id"
                className={cx(inputClass, "pl-9")}
                maxLength={100}
              />
            </div>
          </div>

          <fieldset>
            <legend className="mb-1.5 text-[11.5px] text-fg-dim">Severity</legend>
            <div className="flex flex-wrap gap-1.5">
              {SEVERITIES.map((sev) => {
                const on = severities.includes(sev);
                return (
                  <button
                    key={sev}
                    type="button"
                    aria-pressed={on}
                    onClick={() => toggle("severity", sev, severities)}
                    className={cx(
                      "h-8 rounded-full px-3 font-mono text-[11px] font-medium tracking-wide transition-colors",
                      on ? "text-ink-950" : "bg-ink-800 text-fg-muted hover:text-fg",
                    )}
                    style={on ? { background: SEVERITY_HEX[sev] } : { boxShadow: "inset 0 0 0 1px var(--hairline)" }}
                  >
                    {sev}
                  </button>
                );
              })}
            </div>
          </fieldset>

          {preset !== "history" && (
            <fieldset>
              <legend className="mb-1.5 text-[11.5px] text-fg-dim">Status</legend>
              <div className="flex flex-wrap gap-1.5">
                {statusChoices.map((st) => {
                  const on = statuses.includes(st);
                  return (
                    <button
                      key={st}
                      type="button"
                      aria-pressed={on}
                      onClick={() => toggle("status", st, statuses)}
                      className={cx(
                        "h-8 rounded-full px-3 text-[12px] font-medium transition-colors",
                        on ? "bg-signal text-ink-950" : "bg-ink-800 text-fg-muted shadow-[inset_0_0_0_1px_var(--hairline)] hover:text-fg",
                      )}
                    >
                      {STATE_LABEL[st]}
                    </button>
                  );
                })}
              </div>
            </fieldset>
          )}

          <div>
            <label htmlFor="history-window" className="mb-1.5 block text-[11.5px] text-fg-dim">{preset === "history" ? "Resolved within" : "Seen within"}</label>
            <select id="history-window" value={within} onChange={(e) => setParam("within", e.target.value || null)} className={cx(inputClass, "w-44")}>
              {HISTORY_WINDOWS.map(([v, label]) => <option key={v} value={v}>{label}</option>)}
            </select>
          </div>

          <div>
            <label htmlFor="incident-source" className="mb-1.5 block text-[11.5px] text-fg-dim">Log source</label>
            <select id="incident-source" value={source} onChange={(e) => setParam("source", e.target.value || null)} className={cx(inputClass, "w-44")}>
              <option value="">All sources</option>
              <option value="app">Application</option>
              <option value="audit">PHI access audit</option>
              <option value="auth">Authentication</option>
            </select>
          </div>

          <div>
            <label htmlFor="incident-service" className="mb-1.5 block text-[11.5px] text-fg-dim">Service</label>
            <select id="incident-service" value={service} onChange={(e) => setParam("service", e.target.value || null)} className={cx(inputClass, "w-44")}>
              <option value="">All services</option>
              {serviceNames.map((name) => <option key={name} value={name}>{config.data?.detection.services[name]?.label ?? name}</option>)}
            </select>
          </div>

          {(preset === "active" || preset === "all") && (
            <button
              type="button"
              aria-pressed={pinnedOnly}
              onClick={() => setParam("pinned", pinnedOnly ? null : "1")}
              className={cx(
                "inline-flex h-8 items-center gap-1.5 rounded-full px-3 text-[12px] font-medium transition-colors",
                pinnedOnly ? "bg-signal text-ink-950" : "bg-ink-800 text-fg-muted shadow-[inset_0_0_0_1px_var(--hairline)] hover:text-fg",
              )}
            >
              <PushPin size={13} weight={pinnedOnly ? "fill" : "regular"} /> Pinned only
            </button>
          )}

          <div>
            <label htmlFor="incident-sort" className="mb-1.5 block text-[11.5px] text-fg-dim">Sort by</label>
            <select id="incident-sort" value={sort} onChange={(e) => setParam("sort", e.target.value === "priority" ? null : e.target.value)} className={cx(inputClass, "w-56")}>
              {SORT_OPTIONS.map(([v, label]) => <option key={v} value={v}>{label}</option>)}
            </select>
          </div>

          {filtered && (
            <button
              type="button"
              onClick={() => { setQInput(""); setParams({}, { replace: true }); setLimit(PAGE); }}
              className="h-8 text-[12.5px] text-fg-muted underline-offset-2 hover:text-fg hover:underline"
            >
              Clear filters
            </button>
          )}
        </div>
      </Panel>

      <Panel>
        {isLoading ? (
          <SkeletonRows rows={6} />
        ) : error ? (
          <ErrorState error={error} onRetry={() => refetch()} />
        ) : !data || data.items.length === 0 ? (
          <EmptyState
            icon={<ShieldCheck size={22} />}
            title={filtered ? "No incidents match these filters" : EMPTY_COPY[preset].title}
            body={filtered ? "Try a different search or clear the filters." : EMPTY_COPY[preset].body}
            className="py-16"
          />
        ) : (
          <>
            <div className="flex items-center justify-between px-5 py-3 text-[12px] text-fg-dim" aria-live="polite">
              <span>
                Showing <span className="font-mono text-fg-muted">{data.items.length}</span> of{" "}
                <span className="font-mono text-fg-muted">{data.total}</span>
              </span>
              {isFetching && <span>Updating...</span>}
            </div>
            <IncidentRows items={data.items} showActions={preset !== "history"} />
            {data.total > data.items.length && (
              <div className="border-t border-[var(--hairline)] p-3 text-center">
                <button
                  type="button"
                  onClick={() => setLimit((l) => l + PAGE)}
                  className="h-9 rounded-[var(--radius-control)] px-4 text-[13px] font-medium text-fg-muted hover:bg-ink-800 hover:text-fg"
                >
                  Show {Math.min(PAGE, data.total - data.items.length)} more
                </button>
              </div>
            )}
          </>
        )}
      </Panel>
    </div>
  );
}

export function IncidentRows({ items, showActions = true, dense }: { items: Incident[]; showActions?: boolean; dense?: boolean }) {
  const now = Date.now();
  return (
    <>
      {/* Wide screens: a real table so columns line up and assistive tech gets row/column headers. */}
      <div className="hidden overflow-x-auto md:block">
        <table className="w-full border-collapse text-left text-[13px]">
          <caption className="sr-only">Incidents</caption>
          <thead>
            <tr className="border-y border-[var(--hairline)] text-[11.5px] text-fg-dim">
              <th scope="col" className="w-10 py-2.5 pl-4 pr-1 font-medium"><span className="sr-only">Pinned</span></th>
              <th scope="col" className="px-2 py-2.5 font-medium">ID</th>
              <th scope="col" className="px-2 py-2.5 font-medium">Incident</th>
              <th scope="col" className="px-2 py-2.5 font-medium">Severity</th>
              <th scope="col" className="px-2 py-2.5 font-medium">Risk score</th>
              {!dense && <th scope="col" className="px-2 py-2.5 font-medium">Trend</th>}
              <th scope="col" className="px-2 py-2.5 font-medium">Status</th>
              {!dense && <th scope="col" className="px-2 py-2.5 font-medium">First seen</th>}
              <th scope="col" className="px-2 py-2.5 font-medium">Last seen</th>
              {!dense && <th scope="col" className="px-2 py-2.5 text-right font-medium">Occurrences</th>}
              {showActions && <th scope="col" className="py-2.5 pl-2 pr-4 text-right font-medium">Actions</th>}
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--hairline)]">
            {items.map((i) => (
              <tr key={i.id} className="align-middle transition-colors hover:bg-ink-800/50">
                <td className="py-3 pl-4 pr-1">
                  {showActions ? <PinButton incident={i} /> : i.pinned ? <PushPin size={16} weight="fill" className="text-signal" aria-label="Pinned" /> : null}
                </td>
                <td className="px-2 py-3 font-mono text-fg-muted">#{i.id}</td>
                <td className="max-w-[320px] px-2 py-3">
                  <Link to={`/app/incidents/${i.id}`} className="block truncate font-medium text-fg hover:text-signal">{i.title}</Link>
                  <span className="block truncate text-[11.5px] text-fg-dim">Source: {i.source} · <EvidenceQualityChip quality={i.evidence_quality} count={i.evidence_count} />{i.reopen_count ? ` · reopened ${i.reopen_count}x` : ""}</span>
                </td>
                <td className="px-2 py-3"><SeverityBadge severity={i.severity} size="sm" /></td>
                <td className="px-2 py-3"><RiskScore incident={i} /></td>
                {!dense && <td className="px-2 py-3"><TrendChip incident={i} /></td>}
                <td className="px-2 py-3"><StateBadge state={i.state} /></td>
                {!dense && <td className="whitespace-nowrap px-2 py-3 text-fg-muted" title={stamp(i.first_seen_at)}>{ago(i.first_seen_at, now)}</td>}
                <td className="whitespace-nowrap px-2 py-3 text-fg-muted" title={stamp(i.last_seen_at)}>{ago(i.last_seen_at, now)}</td>
                {!dense && <td className="px-2 py-3 text-right font-mono tabular text-fg">{i.occurrence_count}</td>}
                {showActions && <td className="py-3 pl-2 pr-4"><div className="flex justify-end"><IncidentActions incident={i} compact /></div></td>}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Phones: one card per incident, same fields, same text labels. */}
      <ul className="divide-y divide-[var(--hairline)] md:hidden">
        {items.map((i) => (
          <li key={i.id} className="space-y-2.5 px-4 py-4">
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <Link to={`/app/incidents/${i.id}`} className="block font-medium text-fg hover:text-signal">{i.title}</Link>
                <p className="mt-0.5 text-[11.5px] text-fg-dim">
                  <span className="font-mono">#{i.id}</span> · Source: {i.source}
                  {i.pinned && <span className="ml-1.5 inline-flex items-center gap-1 text-signal"><PushPin size={11} weight="fill" /> Pinned</span>}
                </p>
              </div>
              <SeverityBadge severity={i.severity} size="sm" />
            </div>
            <dl className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-[12px]">
              <div><dt className="text-fg-dim">Status</dt><dd><StateBadge state={i.state} /></dd></div>
              <div><dt className="text-fg-dim">Risk score</dt><dd><RiskScore incident={i} /></dd></div>
              <div><dt className="text-fg-dim">First seen</dt><dd className="text-fg-muted">{ago(i.first_seen_at, now)}</dd></div>
              <div><dt className="text-fg-dim">Last seen</dt><dd className="text-fg-muted">{ago(i.last_seen_at, now)}</dd></div>
              <div><dt className="text-fg-dim">Occurrences</dt><dd className="font-mono text-fg">{i.occurrence_count}</dd></div>
              <div><dt className="text-fg-dim">Risk trend</dt><dd><TrendChip incident={i} /></dd></div>
              <div><dt className="text-fg-dim">Evidence</dt><dd><EvidenceQualityChip quality={i.evidence_quality} count={i.evidence_count} /></dd></div>
            </dl>
            {showActions && <IncidentActions incident={i} compact />}
          </li>
        ))}
      </ul>
    </>
  );
}
