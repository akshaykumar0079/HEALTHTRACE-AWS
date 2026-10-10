import { useEffect, useRef } from "react";
import { useNavigate } from "react-router";
import { AnimatePresence, motion } from "motion/react";
import { CheckCircle, WarningOctagon, X } from "@phosphor-icons/react";
import { useToasts, toast } from "./toast";
import { useLive } from "@/lib/live";
import { SeverityBadge } from "@/components/ui";
import { KIND_LABEL, SEVERITY_HEX, SEVERITY_ORDER, subjectOf } from "@/lib/format";

/**
 * One toast when an anomaly opens at HIGH/CRITICAL or escalates into it, not
 * one per alert: an active anomaly keeps attaching an alert every 5 seconds.
 */
function useAnomalyArrivals() {
  const incidents = useLive((s) => s.incidents);
  const alerts = useLive((s) => s.alerts);
  const replaying = useLive((s) => s.replay?.active ?? false);
  const hydrated = useLive((s) => s.hydrated);
  const known = useRef<Map<number, number> | null>(null);
  useEffect(() => {
    if (!hydrated) return;
    const current = new Map(Object.values(incidents).map((i) => [i.id, SEVERITY_ORDER[i.peak_severity]]));
    if (known.current === null) {
      known.current = current;
      return;
    }
    for (const inc of Object.values(incidents)) {
      const rank = SEVERITY_ORDER[inc.peak_severity];
      const before = known.current.get(inc.id);
      const loud = rank >= SEVERITY_ORDER.HIGH && inc.state !== "RESOLVED";
      if (!replaying && loud && (before === undefined || rank > before)) {
        const alert = alerts.find((a) => a.incident_id === inc.id);
        if (alert) toast.alert({ ...alert, severity: inc.peak_severity });
      }
    }
    known.current = current;
  }, [incidents, alerts, replaying, hydrated]);
}

export function Toaster() {
  useAnomalyArrivals();
  const items = useToasts((s) => s.items);
  const dismiss = useToasts((s) => s.dismiss);
  const navigate = useNavigate();

  return (
    <div className="pointer-events-none fixed bottom-4 right-4 z-[70] flex w-[min(380px,calc(100vw-32px))] flex-col gap-2" aria-live="polite">
      <AnimatePresence initial={false}>
        {items.map((t) => {
          const accent = t.alert ? SEVERITY_HEX[t.alert.severity] : t.kind === "error" ? SEVERITY_HEX.CRITICAL : "#56dcc8";
          return (
            <motion.div
              key={t.id}
              layout
              initial={{ opacity: 0, y: 16, scale: 0.97 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, x: 24, transition: { duration: 0.2 } }}
              transition={{ type: "spring", stiffness: 380, damping: 32 }}
              className="pointer-events-auto relative overflow-hidden rounded-[14px] bg-ink-800/95 p-3.5 pr-10 shadow-[inset_0_0_0_1px_var(--hairline-strong),0_24px_60px_-20px_rgb(0_0_0/0.85)] backdrop-blur-xl"
              role={t.kind === "error" || t.kind === "alert" ? "alert" : "status"}
            >
              <span className="absolute inset-y-0 left-0 w-[3px]" style={{ background: accent }} aria-hidden />
              {t.alert ? (
                <button
                  className="block w-full text-left"
                  onClick={() => {
                    if (t.alert?.incident_id) navigate(`/app/incidents/${t.alert.incident_id}`);
                    dismiss(t.id);
                  }}
                >
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={t.alert.severity} size="sm" />
                    <span className="truncate text-[12.5px] font-medium text-fg">
                      {subjectOf(t.alert)}: {KIND_LABEL[t.alert.kind]}
                    </span>
                  </div>
                  <p className="mt-1.5 line-clamp-2 text-[12px] leading-relaxed text-fg-muted">{t.alert.explanation}</p>
                  <p className="mt-1.5 text-[11.5px] font-medium text-signal">Investigate</p>
                </button>
              ) : (
                <div className="flex gap-2.5">
                  {t.kind === "error" ? (
                    <WarningOctagon size={17} className="mt-0.5 shrink-0 text-sev-critical" />
                  ) : (
                    <CheckCircle size={17} className="mt-0.5 shrink-0 text-signal" />
                  )}
                  <div className="min-w-0">
                    <p className="text-[13px] font-medium text-fg">{t.title}</p>
                    {t.body && <p className="mt-0.5 text-[12px] leading-relaxed text-fg-muted">{t.body}</p>}
                  </div>
                </div>
              )}
              <button
                onClick={() => dismiss(t.id)}
                className="absolute right-2.5 top-2.5 grid size-6 place-items-center rounded-md text-fg-dim hover:bg-ink-700 hover:text-fg"
                aria-label="Dismiss"
              >
                <X size={13} />
              </button>
            </motion.div>
          );
        })}
      </AnimatePresence>
    </div>
  );
}
