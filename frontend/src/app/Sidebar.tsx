import { NavLink } from "react-router";
import { motion } from "motion/react";
import { CaretDoubleLeft } from "@phosphor-icons/react";
import * as Tooltip from "@radix-ui/react-tooltip";
import { NAV } from "./nav";
import { cx } from "@/components/ui";
import { useLive, activeIncidents } from "@/lib/live";
import { SEVERITY_HEX } from "@/lib/format";
import { Logo } from "./Logo";

export function Sidebar({ collapsed, onToggle, onNavigate }: { collapsed: boolean; onToggle?: () => void; onNavigate?: () => void }) {
  const incidents = useLive((s) => s.incidents);
  const active = activeIncidents(incidents);
  const worst = active[0]?.peak_severity;

  return (
    <Tooltip.Provider delayDuration={200} disableHoverableContent>
      <nav aria-label="Primary" className="flex h-full flex-col">
        <div className={cx("flex h-16 items-center", collapsed ? "justify-center px-0" : "px-5")}>
          <NavLink to="/" className="flex items-center gap-2.5 rounded-lg" aria-label="HEALTHTRACE home">
            <Logo size={26} />
            {!collapsed && <span className="text-[13.5px] font-semibold tracking-[0.14em] text-fg">HEALTHTRACE</span>}
          </NavLink>
        </div>

        <div className="flex-1 overflow-y-auto px-3 pb-4">
          {(["main", "tools"] as const).map((group) => (
            <ul
              key={group}
              aria-label={group === "tools" ? "Diagnostics" : undefined}
              className={cx("space-y-0.5", group === "tools" && "mt-6 border-t border-[var(--hairline)] pt-4")}
            >
              {group === "tools" && !collapsed && <li className="px-3 pb-1 text-[10.5px] font-medium uppercase tracking-[0.14em] text-fg-dim">Diagnostics</li>}
              {NAV.filter((n) => n.group === group).map((item) => {
                const badge = item.to === "/app/incidents" && active.length > 0 ? active.length : null;
                const link = (
                  <NavLink
                    to={item.to}
                    aria-label={badge !== null ? `${item.label}, ${badge} active` : item.label}
                    end={item.to === "/app"}
                    onClick={onNavigate}
                    className={({ isActive }) =>
                      cx(
                        "group relative flex h-9 items-center gap-3 rounded-[var(--radius-control)] text-[13px] font-medium transition-colors duration-200",
                        collapsed ? "justify-center px-0" : "px-3",
                        isActive ? "text-fg" : "text-fg-dim hover:bg-ink-800 hover:text-fg-muted",
                      )
                    }
                  >
                    {({ isActive }) => (
                      <>
                        {isActive && (
                          <motion.span
                            layoutId="nav-active"
                            className="absolute inset-0 rounded-[var(--radius-control)] bg-ink-750 shadow-[inset_0_0_0_1px_var(--hairline-strong),inset_0_1px_0_rgb(255_255_255/0.04)]"
                            transition={{ type: "spring", stiffness: 480, damping: 38 }}
                          />
                        )}
                        <item.icon
                          size={18}
                          weight={isActive ? "regular" : "light"}
                          className={cx("relative shrink-0", isActive && "text-signal")}
                        />
                        {!collapsed && <span className="relative flex-1 truncate">{item.label}</span>}
                        {badge !== null && (
                          <span
                            className={cx(
                              "relative rounded-full font-mono text-[10.5px] font-medium tabular",
                              collapsed ? "absolute right-1 top-1 size-2 p-0" : "px-1.5 py-0.5",
                            )}
                            style={{
                              color: worst ? SEVERITY_HEX[worst] : undefined,
                              background: worst ? `${SEVERITY_HEX[worst]}${collapsed ? "" : "1c"}` : undefined,
                            }}
                            aria-label={`${badge} active incidents`}
                          >
                            {collapsed ? "" : badge}
                          </span>
                        )}
                      </>
                    )}
                  </NavLink>
                );
                return (
                  <li key={item.to}>
                    {collapsed ? (
                      <Tooltip.Root>
                        <Tooltip.Trigger asChild>{link}</Tooltip.Trigger>
                        <Tooltip.Portal>
                          <Tooltip.Content
                            side="right"
                            sideOffset={10}
                            className="z-50 rounded-lg bg-ink-700 px-2.5 py-1.5 text-[12px] text-fg shadow-[inset_0_0_0_1px_var(--hairline-strong)]"
                          >
                            {item.label}
                          </Tooltip.Content>
                        </Tooltip.Portal>
                      </Tooltip.Root>
                    ) : (
                      link
                    )}
                  </li>
                );
              })}
            </ul>
          ))}
        </div>

        {onToggle && (
          <div className="border-t border-[var(--hairline)] p-3">
            <button
              onClick={onToggle}
              aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
              aria-expanded={!collapsed}
              className={cx(
                "flex h-9 w-full items-center gap-3 rounded-[var(--radius-control)] text-[12.5px] text-fg-dim transition-colors hover:bg-ink-800 hover:text-fg-muted",
                collapsed ? "justify-center" : "px-3",
              )}
            >
              <CaretDoubleLeft size={16} className={cx("transition-transform duration-300", collapsed && "rotate-180")} />
              {!collapsed && "Collapse"}
            </button>
          </div>
        )}
      </nav>
    </Tooltip.Provider>
  );
}
