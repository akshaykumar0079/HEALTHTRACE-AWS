import { useEffect, useState } from "react";
import { useNavigate } from "react-router";
import { Command } from "cmdk";
import * as Dialog from "@radix-ui/react-dialog";
import { useQuery, useMutation } from "@tanstack/react-query";
import { motion, AnimatePresence } from "motion/react";
import { Broadcast, Graph, Lightning, MagnifyingGlass, PaperPlaneTilt, Terminal, Waveform } from "@phosphor-icons/react";
import { NAV } from "./nav";
import { api } from "@/lib/api";
import { activeIncidents, useLive } from "@/lib/live";
import { serviceLabel } from "@/lib/format";
import { SeverityBadge } from "@/components/ui";
import { toast } from "./toast";

const itemClass =
  "flex h-10 cursor-default select-none items-center gap-3 rounded-[10px] px-3 text-[13px] text-fg-muted data-[selected=true]:bg-ink-700 data-[selected=true]:text-fg";
const groupHeading =
  "[&_[cmdk-group-heading]]:px-3 [&_[cmdk-group-heading]]:pb-1.5 [&_[cmdk-group-heading]]:pt-3 [&_[cmdk-group-heading]]:text-[11px] [&_[cmdk-group-heading]]:text-fg-dim";

export function CommandPalette({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const navigate = useNavigate();
  const services = useLive((s) => s.services);
  const incidents = useLive((s) => s.incidents);
  const [search, setSearch] = useState("");
  const scenarios = useQuery({ queryKey: ["scenarios"], queryFn: api.scenarios, staleTime: 300_000, enabled: open });
  const inject = useMutation({
    mutationFn: (name: string) => api.inject(name, name === "recovery" ? 30 : 90),
    onSuccess: (r) => toast.success(`Injected ${r.scenario.replaceAll("_", " ")}`, "The generator picks it up within a second."),
    onError: (e) => toast.error("Could not inject scenario", e instanceof Error ? e.message : undefined),
  });
  const testAlert = useMutation({
    mutationFn: api.awsTestAlert,
    onSuccess: (r) =>
      r.cloudwatch.ok || r.sns.ok
        ? toast.success("Test alert sent", `CloudWatch: ${r.cloudwatch.detail}. SNS: ${r.sns.detail}.`)
        : toast.error("Test alert not delivered", `CloudWatch: ${r.cloudwatch.detail}. SNS: ${r.sns.detail}.`),
    onError: (e) => toast.error("Test alert failed", e instanceof Error ? e.message : undefined),
  });

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        onOpenChange(!open);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onOpenChange]);

  useEffect(() => {
    if (!open) setSearch("");
  }, [open]);

  const go = (to: string) => {
    onOpenChange(false);
    navigate(to);
  };
  const run = (fn: () => void) => {
    onOpenChange(false);
    fn();
  };

  const active = activeIncidents(incidents).slice(0, 6);

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <AnimatePresence>
        {open && (
          <Dialog.Portal forceMount>
            <Dialog.Overlay asChild forceMount>
              <motion.div
                className="fixed inset-0 z-50 bg-ink-950/70 backdrop-blur-sm"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.18 }}
              />
            </Dialog.Overlay>
            <Dialog.Content asChild forceMount aria-describedby={undefined}>
              <motion.div
                className="fixed left-1/2 top-[14vh] z-50 w-[min(640px,calc(100vw-24px))] -translate-x-1/2"
                initial={{ opacity: 0, y: -12, scale: 0.98 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, y: -8, scale: 0.985 }}
                transition={{ duration: 0.28, ease: [0.16, 1, 0.3, 1] }}
              >
                <Dialog.Title className="sr-only">Command palette</Dialog.Title>
                <Command
                  label="Command palette"
                  className="bezel shadow-[0_40px_120px_-30px_rgb(0_0_0/0.9)]"
                  loop
                >
                  <div className="bezel-core overflow-hidden">
                    <div className="flex items-center gap-3 border-b border-[var(--hairline)] px-4">
                      <MagnifyingGlass size={17} className="text-fg-dim" />
                      <Command.Input
                        value={search}
                        onValueChange={setSearch}
                        placeholder="Jump to a page, service, anomaly or action"
                        className="h-13 flex-1 bg-transparent py-4 text-[14px] text-fg outline-none placeholder:text-fg-dim"
                      />
                      <span className="kbd">Esc</span>
                    </div>
                    <Command.List className="max-h-[min(440px,60vh)] overflow-y-auto p-2">
                      <Command.Empty className="px-3 py-8 text-center text-[13px] text-fg-dim">
                        Nothing matches "{search}".
                      </Command.Empty>

                      {search.trim() && (
                        <Command.Group heading="Logs" className={groupHeading}>
                          <Command.Item
                            value={`search logs ${search}`}
                            onSelect={() => go(`/app/logs?q=${encodeURIComponent(search.trim())}`)}
                            className={itemClass}
                          >
                            <Terminal size={16} /> Search logs for "{search.trim()}"
                          </Command.Item>
                        </Command.Group>
                      )}

                      <Command.Group heading="Navigate" className={groupHeading}>
                        {NAV.map((item) => (
                          <Command.Item
                            key={item.to}
                            value={`${item.label} ${item.keywords ?? ""}`}
                            onSelect={() => go(item.to)}
                            className={itemClass}
                          >
                            <item.icon size={16} weight="light" /> {item.label}
                          </Command.Item>
                        ))}
                      </Command.Group>

                      {active.length > 0 && (
                        <Command.Group heading="Active incidents" className={groupHeading}>
                          {active.map((inc) => (
                            <Command.Item
                              key={inc.id}
                              value={`incident ${inc.id} ${inc.title}`}
                              onSelect={() => go(`/app/incidents/${inc.id}`)}
                              className={itemClass}
                            >
                              <Waveform size={16} />
                              <span className="flex-1 truncate">
                                {inc.title}
                              </span>
                              <SeverityBadge severity={inc.peak_severity} size="sm" />
                            </Command.Item>
                          ))}
                        </Command.Group>
                      )}

                      <Command.Group heading="Services" className={groupHeading}>
                        {Object.values(services).map((svc) => (
                          <Command.Item
                            key={svc.service}
                            value={`service ${svc.service} ${svc.label}`}
                            onSelect={() => go(`/app/services/${svc.service}`)}
                            className={itemClass}
                          >
                            <Graph size={16} weight="light" /> {serviceLabel(svc.service, { [svc.service]: svc.label })}
                          </Command.Item>
                        ))}
                      </Command.Group>

                      <Command.Group heading="Actions" className={groupHeading}>
                        <Command.Item value="open live monitor" onSelect={() => go("/app/monitor")} className={itemClass}>
                          <Broadcast size={16} /> Open live monitor
                        </Command.Item>
                        <Command.Item value="search logs" onSelect={() => go("/app/logs")} className={itemClass}>
                          <Terminal size={16} /> Search logs
                        </Command.Item>
                        <Command.Item value="send aws test alert cloudwatch sns" onSelect={() => run(() => testAlert.mutate())} className={itemClass}>
                          <PaperPlaneTilt size={16} /> Send AWS test alert
                        </Command.Item>
                      </Command.Group>

                      {scenarios.data?.enabled && (
                        <Command.Group heading="Demo scenarios" className={groupHeading}>
                          {scenarios.data.scenarios.map((s) => (
                            <Command.Item
                              key={s.name}
                              value={`inject scenario ${s.label} ${s.name}`}
                              onSelect={() => run(() => inject.mutate(s.name))}
                              className={itemClass}
                            >
                              <Lightning size={16} />
                              <span className="flex-1 truncate">Inject {s.label}</span>
                              <span className="text-[11px] text-fg-dim">{s.expected}</span>
                            </Command.Item>
                          ))}
                        </Command.Group>
                      )}
                    </Command.List>
                  </div>
                </Command>
              </motion.div>
            </Dialog.Content>
          </Dialog.Portal>
        )}
      </AnimatePresence>
    </Dialog.Root>
  );
}
