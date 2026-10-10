import { Link, useNavigate } from "react-router";
import { useQuery } from "@tanstack/react-query";
import * as Dropdown from "@radix-ui/react-dropdown-menu";
import {
  BellSimple,
  CaretUpDown,
  Check,
  Info,
  List,
  MagnifyingGlass,
  ShieldCheck,
  UserCircle,
} from "@phosphor-icons/react";
import { api, getOperatorToken } from "@/lib/api";
import { reconnectNow, useLive } from "@/lib/live";
import { Beacon, SeverityBadge, cx } from "@/components/ui";
import { SimulatedBadge, useFreshness } from "@/components/StatusStrip";
import { SIGNAL_HEX, ago, subjectOf, KIND_LABEL } from "@/lib/format";

const menuContent =
  "z-50 min-w-[240px] rounded-[14px] bg-ink-800/95 p-1.5 text-[13px] shadow-[inset_0_0_0_1px_var(--hairline-strong),0_24px_60px_-20px_rgb(0_0_0/0.8)] backdrop-blur-xl";
const menuItem =
  "flex cursor-default select-none items-center gap-2.5 rounded-[9px] px-2.5 py-2 text-fg-muted outline-none data-[highlighted]:bg-ink-700 data-[highlighted]:text-fg";

export function ConnectionPill() {
  const connection = useLive((s) => s.connection);
  const replay = useLive((s) => s.replay);
  const freshness = useFreshness();
  const replaying = replay?.active;

  const meta =
    connection === "live"
      ? replaying
        ? { label: `REPLAYING ${Math.round((replay?.progress ?? 0) * 100)}%`, color: "#e3b35a", detail: "Catching up on log history" }
        : freshness === "stale"
          ? { label: "STALE", color: "#e3b35a", detail: "Connected, but no recent log events are arriving" }
          : { label: "LIVE", color: SIGNAL_HEX, detail: "Connected and events are flowing" }
      : connection === "connecting"
        ? { label: "CONNECTING", color: "#627085", detail: "Opening WebSocket" }
        : connection === "reconnecting"
          ? { label: "RECONNECTING", color: "#e3b35a", detail: "Connection lost, retrying" }
          : { label: "OFFLINE", color: "#f05a73", detail: "Backend unreachable" };

  return (
    <button
      onClick={connection === "live" ? undefined : reconnectNow}
      title={connection === "live" ? meta.detail : `${meta.detail}. Click to retry now.`}
      className="flex h-8 items-center gap-2 rounded-full bg-ink-800 pl-3 pr-3.5 shadow-[inset_0_0_0_1px_var(--hairline)]"
      aria-live="polite"
    >
      <Beacon color={meta.color} pulse={connection === "live" && freshness === "live"} size={7} />
      <span className="font-mono text-[10.5px] font-medium tracking-[0.12em]" style={{ color: meta.color }}>
        {meta.label}
      </span>
      <span className="hidden text-[11.5px] text-fg-dim xl:inline">{meta.detail}</span>
    </button>
  );
}

function ContextSelector() {
  const { data } = useQuery({ queryKey: ["config"], queryFn: api.config, staleTime: 60_000 });
  const project = data?.deployment.project_name ?? "Medicaid Pipeline";
  const env = data?.deployment.environment ?? "local";
  return (
    <Dropdown.Root>
      <Dropdown.Trigger aria-label="Project and environment" className="flex h-8 items-center gap-2 rounded-[var(--radius-control)] px-2.5 text-left transition-colors hover:bg-ink-800">
        <span className="grid size-6 place-items-center rounded-md bg-signal-deep font-mono text-[10px] font-semibold text-signal">
          {project.slice(0, 2).toUpperCase()}
        </span>
        <span className="hidden min-w-0 sm:block">
          <span className="block truncate text-[12.5px] font-medium leading-tight text-fg">{project}</span>
          <span className="block font-mono text-[10.5px] leading-tight text-fg-dim">{env}</span>
        </span>
        <CaretUpDown size={13} className="text-fg-dim max-sm:hidden" />
      </Dropdown.Trigger>
      <Dropdown.Portal>
        <Dropdown.Content sideOffset={8} align="start" className={menuContent}>
          <Dropdown.Label className="px-2.5 pb-1 pt-1.5 text-[11px] text-fg-dim">Project</Dropdown.Label>
          <Dropdown.Item className={menuItem}>
            <Check size={14} className="text-signal" />
            {project}
          </Dropdown.Item>
          <Dropdown.Label className="px-2.5 pb-1 pt-3 text-[11px] text-fg-dim">Environment</Dropdown.Label>
          <Dropdown.Item className={menuItem}>
            <Check size={14} className="text-signal" />
            <span className="font-mono text-[12px]">{env}</span>
          </Dropdown.Item>
          <Dropdown.Separator className="my-1.5 h-px bg-[var(--hairline)]" />
          <div className="flex gap-2 px-2.5 py-2 text-[11.5px] leading-relaxed text-fg-dim">
            <Info size={14} className="mt-0.5 shrink-0" />
            Each deployment monitors one project and environment. Set PROJECT_NAME and ENVIRONMENT per deployment.
          </div>
        </Dropdown.Content>
      </Dropdown.Portal>
    </Dropdown.Root>
  );
}

function Notifications() {
  const alerts = useLive((s) => s.alerts);
  const navigate = useNavigate();
  const important = alerts.filter((a) => a.severity === "HIGH" || a.severity === "CRITICAL").slice(0, 8);
  const unseen = important.filter((a) => Date.now() - new Date(a.ts).getTime() < 5 * 60_000).length;
  return (
    <Dropdown.Root>
      <Dropdown.Trigger
        className="relative grid size-8 place-items-center rounded-[var(--radius-control)] text-fg-muted transition-colors hover:bg-ink-800 hover:text-fg"
        aria-label={`Notifications${unseen ? `, ${unseen} in the last 5 minutes` : ""}`}
      >
        <BellSimple size={18} />
        {unseen > 0 && <span className="absolute right-1.5 top-1.5 size-2 rounded-full bg-sev-critical ring-2 ring-ink-900" />}
      </Dropdown.Trigger>
      <Dropdown.Portal>
        <Dropdown.Content sideOffset={8} align="end" className={cx(menuContent, "w-[360px]")}>
          <Dropdown.Label className="px-2.5 pb-1.5 pt-1.5 text-[11px] text-fg-dim">High and critical alerts</Dropdown.Label>
          {important.length === 0 && (
            <p className="px-2.5 py-6 text-center text-[12.5px] text-fg-dim">No high or critical alerts yet.</p>
          )}
          {important.map((a) => (
            <Dropdown.Item
              key={`${a.id}-${a.ts}`}
              className={cx(menuItem, "items-start")}
              onSelect={() => a.incident_id && navigate(`/app/incidents/${a.incident_id}`)}
            >
              <SeverityBadge severity={a.severity} size="sm" />
              <span className="min-w-0 flex-1">
                <span className="block truncate text-[12.5px] text-fg">
                  {subjectOf(a)}: {KIND_LABEL[a.kind]}
                </span>
                <span className="block text-[11px] text-fg-dim">{ago(a.ts)}</span>
              </span>
            </Dropdown.Item>
          ))}
          <Dropdown.Separator className="my-1.5 h-px bg-[var(--hairline)]" />
          <Dropdown.Item asChild className={menuItem}>
            <Link to="/app/alerts">View all alerts</Link>
          </Dropdown.Item>
        </Dropdown.Content>
      </Dropdown.Portal>
    </Dropdown.Root>
  );
}

function UserMenu() {
  const hasToken = !!getOperatorToken();
  return (
    <Dropdown.Root>
      <Dropdown.Trigger
        className="grid size-8 place-items-center rounded-full text-fg-muted transition-colors hover:bg-ink-800 hover:text-fg"
        aria-label="Operator menu"
      >
        <UserCircle size={22} weight="light" />
      </Dropdown.Trigger>
      <Dropdown.Portal>
        <Dropdown.Content sideOffset={8} align="end" className={menuContent}>
          <div className="px-2.5 pb-2 pt-1.5">
            <p className="text-[13px] font-medium text-fg">Operator console</p>
            <p className="mt-0.5 text-[11.5px] leading-relaxed text-fg-dim">
              Without a token you have a read-only view. {hasToken ? "An operator token is set for this tab." : "No operator token set."}
            </p>
          </div>
          <Dropdown.Separator className="my-1 h-px bg-[var(--hairline)]" />
          <Dropdown.Item asChild className={menuItem}>
            <Link to="/app/settings#access">
              <ShieldCheck size={15} /> Operator token
            </Link>
          </Dropdown.Item>
          <Dropdown.Item asChild className={menuItem}>
            <Link to="/">Product overview</Link>
          </Dropdown.Item>
        </Dropdown.Content>
      </Dropdown.Portal>
    </Dropdown.Root>
  );
}

export function Topbar({ onMenu, onSearch }: { onMenu: () => void; onSearch: () => void }) {
  return (
    <header className="sticky top-0 z-30 flex h-16 items-center gap-2 border-b border-[var(--hairline)] bg-ink-950/80 px-3 backdrop-blur-xl md:px-5">
      <button
        onClick={onMenu}
        className="grid size-9 place-items-center rounded-[var(--radius-control)] text-fg-muted hover:bg-ink-800 lg:hidden"
        aria-label="Open navigation"
      >
        <List size={20} />
      </button>
      <div className="max-sm:hidden"><ContextSelector /></div>
      <div className="mx-1 hidden h-5 w-px bg-[var(--hairline-strong)] md:block" />
      <ConnectionPill />
      <SimulatedBadge />
      <div className="flex-1" />
      <button
        onClick={onSearch}
        className="flex h-8 items-center gap-2 rounded-[var(--radius-control)] bg-ink-800 pl-2.5 pr-1.5 text-[12.5px] text-fg-dim shadow-[inset_0_0_0_1px_var(--hairline)] transition-colors hover:text-fg-muted md:w-64"
        aria-label="Open command palette"
      >
        <MagnifyingGlass size={15} />
        <span className="hidden flex-1 text-left md:inline">Search or jump to</span>
        <span className="kbd hidden md:inline">Ctrl K</span>
      </button>
      <Notifications />
      <UserMenu />
    </header>
  );
}
