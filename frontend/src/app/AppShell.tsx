import { Suspense, useEffect, useState } from "react";
import { useLocation, useOutlet } from "react-router";
import { AnimatePresence, motion, useReducedMotion } from "motion/react";
import * as Dialog from "@radix-ui/react-dialog";
import { Sidebar } from "./Sidebar";
import { Topbar } from "./Topbar";
import { CommandPalette } from "./CommandPalette";
import { Toaster } from "./Toaster";
import { startLive, useLive } from "@/lib/live";
import { SkeletonRows, cx } from "@/components/ui";
import { SecurityBanner } from "@/components/Security";

const COLLAPSE_KEY = "healthtrace.sidebarCollapsed";

function readCollapsed(): boolean {
  try {
    return localStorage.getItem(COLLAPSE_KEY) === "1";
  } catch {
    return false;
  }
}

function ReplayBanner() {
  const replay = useLive((s) => s.replay);
  if (!replay?.active) return null;
  return (
    <div className="border-b border-[var(--hairline)] bg-[#e3b35a0d] px-5 py-2 text-[12.5px] text-fg-muted">
      <div className="flex items-center gap-3">
        <span className="font-medium text-sev-medium">Replaying log history</span>
        <span className="hidden sm:inline">
          Detection is catching up on logs written before this session. Live updates resume automatically.
        </span>
        <span className="ml-auto font-mono text-fg">{Math.round(replay.progress * 100)}%</span>
      </div>
      <div className="mt-1.5 h-[2px] overflow-hidden rounded-full bg-ink-700">
        <div className="h-full bg-sev-medium transition-[width] duration-700" style={{ width: `${replay.progress * 100}%` }} />
      </div>
    </div>
  );
}

export default function AppShell() {
  const location = useLocation();
  const outlet = useOutlet();
  const reduce = useReducedMotion();
  const [collapsed, setCollapsed] = useState(readCollapsed);
  const [mobileNav, setMobileNav] = useState(false);
  const [palette, setPalette] = useState(false);

  useEffect(() => {
    startLive();
  }, []);

  useEffect(() => {
    try {
      localStorage.setItem(COLLAPSE_KEY, collapsed ? "1" : "0");
    } catch {
      /* ignore */
    }
  }, [collapsed]);

  // Keep the top-level route segment as the transition key so tab/filter
  // changes inside a page don't replay the page entrance.
  const routeKey = location.pathname.split("/").slice(0, 4).join("/");

  return (
    <div className="grain flex min-h-[100dvh] bg-ink-950">
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-[80] focus:rounded-lg focus:bg-ink-700 focus:px-3 focus:py-2">
        Skip to content
      </a>
      <aside
        className={cx(
          "sticky top-0 hidden h-[100dvh] shrink-0 border-r border-[var(--hairline)] bg-ink-900 transition-[width] duration-300 ease-[var(--ease-out-expo)] lg:block",
          collapsed ? "w-[68px]" : "w-[232px]",
        )}
      >
        <Sidebar collapsed={collapsed} onToggle={() => setCollapsed((c) => !c)} />
      </aside>

      <Dialog.Root open={mobileNav} onOpenChange={setMobileNav}>
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 z-50 bg-ink-950/70 backdrop-blur-sm lg:hidden" />
          <Dialog.Content
            className="fixed inset-y-0 left-0 z-50 w-[260px] border-r border-[var(--hairline)] bg-ink-900 lg:hidden"
            aria-describedby={undefined}
          >
            <Dialog.Title className="sr-only">Navigation</Dialog.Title>
            <Sidebar collapsed={false} onNavigate={() => setMobileNav(false)} />
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>

      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar onMenu={() => setMobileNav(true)} onSearch={() => setPalette(true)} />
        <SecurityBanner />
        <ReplayBanner />
        <main id="main" className="relative flex-1">
          <AnimatePresence mode="wait" initial={false}>
            <motion.div
              key={routeKey}
              initial={reduce ? false : { opacity: 0, y: 10, filter: "blur(6px)" }}
              animate={{ opacity: 1, y: 0, filter: "blur(0px)" }}
              exit={reduce ? undefined : { opacity: 0, y: -6, filter: "blur(4px)", transition: { duration: 0.14 } }}
              transition={{ duration: 0.45, ease: [0.16, 1, 0.3, 1] }}
              className="mx-auto w-full max-w-[1600px] px-4 py-6 md:px-8 md:py-8"
            >
              <Suspense fallback={<SkeletonRows rows={8} />}>{outlet}</Suspense>
            </motion.div>
          </AnimatePresence>
        </main>
      </div>

      <CommandPalette open={palette} onOpenChange={setPalette} />
      <Toaster />
    </div>
  );
}
