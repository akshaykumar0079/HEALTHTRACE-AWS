import type { ReactNode } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { Button } from "./ui";

/**
 * Confirmation for actions that change shared state or are hard to undo.
 * Radix Dialog gives focus trapping, Escape to cancel and focus return.
 */
export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  body,
  confirmLabel,
  tone = "primary",
  busy,
  onConfirm,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  body: ReactNode;
  confirmLabel: string;
  tone?: "primary" | "danger";
  busy?: boolean;
  onConfirm: () => void;
}) {
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-[60] bg-ink-950/70 backdrop-blur-sm" />
        <Dialog.Content
          className="fixed left-1/2 top-1/2 z-[61] w-[min(92vw,440px)] -translate-x-1/2 -translate-y-1/2 rounded-[16px] bg-ink-850 p-6 shadow-[inset_0_0_0_1px_var(--hairline-strong),0_30px_80px_-20px_rgb(0_0_0/0.85)]"
          aria-describedby="confirm-body"
        >
          <Dialog.Title className="text-[15px] font-semibold tracking-tight text-fg">{title}</Dialog.Title>
          <div id="confirm-body" className="mt-2 text-[13px] leading-relaxed text-fg-muted">
            {body}
          </div>
          <div className="mt-6 flex justify-end gap-2">
            <Dialog.Close asChild>
              <Button variant="ghost" size="md">Cancel</Button>
            </Dialog.Close>
            <Button variant={tone === "danger" ? "danger" : "primary"} busy={busy} onClick={onConfirm}>
              {confirmLabel}
            </Button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
