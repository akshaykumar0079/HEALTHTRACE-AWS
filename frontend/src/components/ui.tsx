import { forwardRef, useEffect, useRef, type ButtonHTMLAttributes, type ReactNode } from "react";
import { animate, motion, useMotionValue, useReducedMotion, useTransform } from "motion/react";
import clsx from "clsx";
import { ArrowClockwise, WarningOctagon, WifiSlash } from "@phosphor-icons/react";
import type { IncidentState, Severity } from "@/lib/types";
import { SEVERITY_HEX, STATE_LABEL } from "@/lib/format";

export const cx = clsx;

// -- buttons --------------------------------------------------------------------

type ButtonVariant = "primary" | "secondary" | "ghost" | "danger";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: "sm" | "md";
  icon?: ReactNode;
  busy?: boolean;
}

const variants: Record<ButtonVariant, string> = {
  primary:
    "bg-signal text-ink-950 hover:bg-[#6ee7d5] shadow-[inset_0_1px_0_rgb(255_255_255/0.35),0_10px_30px_-12px_rgb(86_220_200/0.55)]",
  secondary:
    "bg-ink-750 text-fg hover:bg-ink-700 shadow-[inset_0_0_0_1px_var(--hairline-strong),inset_0_1px_0_rgb(255_255_255/0.04)]",
  ghost: "text-fg-muted hover:text-fg hover:bg-ink-750",
  danger:
    "bg-ink-750 text-sev-critical hover:bg-[#2a1520] shadow-[inset_0_0_0_1px_rgb(240_90_115/0.3)]",
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = "secondary", size = "md", icon, busy, className, children, disabled, ...rest },
  ref,
) {
  return (
    <button
      ref={ref}
      disabled={disabled || busy}
      className={cx(
        "inline-flex select-none items-center justify-center gap-2 whitespace-nowrap rounded-[var(--radius-control)] font-medium transition-[background-color,transform,color,box-shadow] duration-200 ease-[var(--ease-out-expo)] active:scale-[0.98] disabled:pointer-events-none disabled:opacity-45",
        size === "sm" ? "h-8 px-3 text-[12.5px]" : "h-9 px-3.5 text-[13px]",
        variants[variant],
        className,
      )}
      {...rest}
    >
      {busy ? <ArrowClockwise className="animate-spin" size={14} /> : icon}
      {children}
    </button>
  );
});

// -- severity / state -------------------------------------------------------------

export function SeverityBadge({ severity, size = "md" }: { severity: Severity; size?: "sm" | "md" }) {
  const color = SEVERITY_HEX[severity];
  return (
    <span
      className={cx(
        "inline-flex items-center gap-1.5 rounded-full font-mono font-medium tracking-wide",
        size === "sm" ? "px-2 py-0.5 text-[10px]" : "px-2.5 py-1 text-[11px]",
      )}
      style={{ color, background: `${color}14`, boxShadow: `inset 0 0 0 1px ${color}33` }}
    >
      <span className="size-1.5 rounded-full" style={{ background: color }} aria-hidden />
      {severity}
    </span>
  );
}

export function StateBadge({ state }: { state: IncidentState }) {
  const tone =
    state === "OPEN"
      ? "text-fg bg-ink-700"
      : state === "ACKNOWLEDGED"
        ? "text-sev-medium bg-[#e3b35a12]"
        : state === "INVESTIGATING"
          ? "text-signal bg-[#56dcc812]"
          : "text-fg-dim bg-ink-800";
  return (
    <span className={cx("inline-flex items-center rounded-full px-2.5 py-1 text-[11px] font-medium", tone)}>
      {STATE_LABEL[state]}
    </span>
  );
}

/** A semantic live indicator (connection / stream state), never decoration. */
export function Beacon({ color, pulse = true, size = 8 }: { color: string; pulse?: boolean; size?: number }) {
  const reduce = useReducedMotion();
  return (
    <span className="relative inline-flex shrink-0" style={{ width: size, height: size }} aria-hidden>
      {pulse && !reduce && (
        <span className="absolute inset-0 rounded-full animate-pulse-ring" style={{ background: color }} />
      )}
      <span className="relative rounded-full" style={{ width: size, height: size, background: color }} />
    </span>
  );
}

// -- containers -------------------------------------------------------------------

export function Bezel({ className, coreClassName, children }: { className?: string; coreClassName?: string; children: ReactNode }) {
  return (
    <div className={cx("bezel", className)}>
      <div className={cx("bezel-core h-full", coreClassName)}>{children}</div>
    </div>
  );
}

export function Panel({ className, children, as: As = "section" }: { className?: string; children: ReactNode; as?: "section" | "div" | "article" }) {
  return <As className={cx("panel", className)}>{children}</As>;
}

export function PanelHeader({
  title,
  description,
  actions,
  className,
}: {
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  className?: string;
}) {
  return (
    <header className={cx("flex items-start justify-between gap-4 px-5 pt-4 pb-3", className)}>
      <div className="min-w-0">
        <h2 className="text-[13.5px] font-medium tracking-tight text-fg">{title}</h2>
        {description && <p className="mt-0.5 text-[12.5px] leading-relaxed text-fg-dim">{description}</p>}
      </div>
      {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
    </header>
  );
}

export function PageHeader({ title, description, actions }: { title: string; description?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="flex flex-col gap-4 pb-6 md:flex-row md:items-end md:justify-between">
      <div className="min-w-0">
        <h1 className="text-[26px] font-semibold leading-tight tracking-[-0.02em] text-fg md:text-[30px]">{title}</h1>
        {description && <div className="mt-1.5 max-w-[68ch] text-[13.5px] leading-relaxed text-fg-muted">{description}</div>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

// -- states -----------------------------------------------------------------------

export function EmptyState({ icon, title, body, action, className }: {
  icon?: ReactNode; title: string; body?: ReactNode; action?: ReactNode; className?: string;
}) {
  return (
    <div className={cx("flex flex-col items-center justify-center px-6 py-14 text-center", className)}>
      {icon && (
        <div className="mb-4 grid size-11 place-items-center rounded-full bg-ink-750 text-signal shadow-[inset_0_0_0_1px_var(--hairline-strong)]">
          {icon}
        </div>
      )}
      <p className="text-[14px] font-medium text-fg">{title}</p>
      {body && <p className="mt-1.5 max-w-[46ch] text-[12.5px] leading-relaxed text-fg-dim">{body}</p>}
      {action && <div className="mt-5">{action}</div>}
    </div>
  );
}

export function ErrorState({ error, onRetry, className }: { error: unknown; onRetry?: () => void; className?: string }) {
  const offline = error instanceof Error && /unreachable/i.test(error.message);
  return (
    <div className={cx("flex flex-col items-center justify-center px-6 py-12 text-center", className)}>
      <div className="mb-4 grid size-11 place-items-center rounded-full bg-[#f05a7312] text-sev-critical">
        {offline ? <WifiSlash size={20} /> : <WarningOctagon size={20} />}
      </div>
      <p className="text-[14px] font-medium text-fg">{offline ? "Backend unreachable" : "Could not load this view"}</p>
      <p className="mt-1.5 max-w-[46ch] text-[12.5px] leading-relaxed text-fg-dim">
        {error instanceof Error ? error.message : "An unexpected error occurred."}
      </p>
      {onRetry && (
        <Button className="mt-5" size="sm" icon={<ArrowClockwise size={14} />} onClick={onRetry}>
          Try again
        </Button>
      )}
    </div>
  );
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={cx("skeleton", className)} aria-hidden />;
}

export function SkeletonRows({ rows = 6, className }: { rows?: number; className?: string }) {
  return (
    <div className={cx("space-y-3 p-5", className)} aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="flex items-center gap-3">
          <Skeleton className="h-5 w-16" />
          <Skeleton className="h-4 flex-1" />
          <Skeleton className="h-4 w-20" />
        </div>
      ))}
    </div>
  );
}

// -- numbers ------------------------------------------------------------------------

/** Tweens between values off the React render path (motion value -> DOM text). */
export function AnimatedNumber({ value, format, className }: { value: number; format: (v: number) => string; className?: string }) {
  const reduce = useReducedMotion();
  const mv = useMotionValue(value);
  const text = useTransform(mv, (v) => format(v));
  const first = useRef(true);
  useEffect(() => {
    if (first.current || reduce) {
      first.current = false;
      mv.set(value);
      return;
    }
    const controls = animate(mv, value, { duration: 0.8, ease: [0.16, 1, 0.3, 1] });
    return () => controls.stop();
  }, [value, mv, reduce]);
  return <motion.span className={cx("tabular", className)}>{text}</motion.span>;
}

// -- inputs -------------------------------------------------------------------------

export function Segmented<T extends string>({
  value,
  options,
  onChange,
  label,
  size = "md",
}: {
  value: T;
  options: { value: T; label: ReactNode }[];
  onChange: (value: T) => void;
  label: string;
  size?: "sm" | "md";
}) {
  return (
    <div role="radiogroup" aria-label={label} className="relative inline-flex rounded-[var(--radius-control)] bg-ink-800 p-0.5 shadow-[inset_0_0_0_1px_var(--hairline)]">
      {options.map((opt) => {
        const active = opt.value === value;
        return (
          <button
            key={opt.value}
            role="radio"
            aria-checked={active}
            onClick={() => onChange(opt.value)}
            className={cx(
              "relative z-0 rounded-[8px] font-medium transition-colors duration-200",
              size === "sm" ? "h-7 px-2.5 text-[11.5px]" : "h-8 px-3 text-[12.5px]",
              active ? "text-fg" : "text-fg-dim hover:text-fg-muted",
            )}
          >
            {active && (
              <motion.span
                layoutId={`seg-${label}`}
                className="absolute inset-0 -z-10 rounded-[8px] bg-ink-700 shadow-[inset_0_1px_0_rgb(255_255_255/0.05)]"
                transition={{ type: "spring", stiffness: 420, damping: 36 }}
              />
            )}
            {opt.label}
          </button>
        );
      })}
    </div>
  );
}

export function Field({ label, htmlFor, hint, children }: { label: string; htmlFor: string; hint?: ReactNode; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-2">
      <label htmlFor={htmlFor} className="text-[12.5px] font-medium text-fg-muted">
        {label}
      </label>
      {children}
      {hint && <p className="text-[12px] leading-relaxed text-fg-dim">{hint}</p>}
    </div>
  );
}

export const inputClass =
  "h-9 w-full rounded-[var(--radius-control)] bg-ink-900 px-3 text-[13px] text-fg placeholder:text-fg-dim shadow-[inset_0_0_0_1px_var(--hairline-strong)] outline-none transition-shadow focus:shadow-[inset_0_0_0_1px_var(--color-signal)]";

export function Stat({ label, children, sub, className }: { label: string; children: ReactNode; sub?: ReactNode; className?: string }) {
  return (
    <div className={cx("min-w-0", className)}>
      <p className="text-[12px] text-fg-dim">{label}</p>
      <div className="mt-1 font-mono text-[20px] font-medium tracking-tight text-fg tabular">{children}</div>
      {sub && <div className="mt-0.5 text-[11.5px] text-fg-dim">{sub}</div>}
    </div>
  );
}
