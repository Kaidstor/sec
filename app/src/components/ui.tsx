import clsx from "clsx";
import { Loader2, RefreshCw } from "lucide-react";
import {
  ButtonHTMLAttributes,
  ComponentProps,
  LabelHTMLAttributes,
  ReactNode,
  SelectHTMLAttributes,
  useEffect,
} from "react";
import { useApp } from "../store";

export const cn = clsx;

type ButtonVariant = "primary" | "ghost" | "danger";

export function Button({
  variant = "ghost",
  className,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant }) {
  return (
    <button
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-[12px] font-medium transition-colors",
        "disabled:opacity-40 disabled:pointer-events-none",
        variant === "primary" && "bg-sky-600 text-white hover:bg-sky-500 active:bg-sky-600",
        variant === "ghost" && "text-zinc-300 hover:bg-zinc-800 active:bg-zinc-700/80",
        variant === "danger" && "bg-red-600/90 text-white hover:bg-red-500 active:bg-red-600",
        className,
      )}
      {...props}
    />
  );
}

export function IconButton({ className, title, ...props }: ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      title={title}
      className={cn(
        "inline-flex items-center justify-center rounded p-1 text-zinc-400",
        "hover:bg-zinc-700/60 hover:text-zinc-100 transition-colors",
        "disabled:opacity-40 disabled:pointer-events-none",
        className,
      )}
      {...props}
    />
  );
}

export function RefreshButton({
  loading,
  onClick,
  title = "Обновить",
}: {
  loading: boolean;
  onClick: () => void;
  title?: string;
}) {
  return (
    <IconButton title={title} disabled={loading} onClick={onClick}>
      {loading ? <Loader2 size={13} className="animate-spin" /> : <RefreshCw size={13} />}
    </IconButton>
  );
}

export function Input({ className, ...props }: ComponentProps<"input">) {
  return (
    <input
      spellCheck={false}
      autoCorrect="off"
      autoCapitalize="off"
      autoComplete="off"
      className={cn(
        "h-7.5 w-full rounded-md border border-zinc-700 bg-zinc-900 px-2 text-[13px]",
        "text-zinc-100 placeholder:text-zinc-600",
        "focus:border-sky-600 focus:outline-none",
        className,
      )}
      {...props}
    />
  );
}

export function Textarea({ className, ...props }: ComponentProps<"textarea">) {
  return (
    <textarea
      spellCheck={false}
      autoCorrect="off"
      autoCapitalize="off"
      className={cn(
        "w-full rounded-md border border-zinc-700 bg-zinc-900 px-2 py-1 font-mono text-[12px]",
        "text-zinc-100 placeholder:text-zinc-600",
        "focus:border-sky-600 focus:outline-none",
        className,
      )}
      {...props}
    />
  );
}

export function Select({ className, ...props }: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select
      className={cn(
        "h-7.5 rounded-md border border-zinc-700 bg-zinc-900 px-1.5 text-[12px]",
        "text-zinc-200 focus:border-sky-600 focus:outline-none",
        className,
      )}
      {...props}
    />
  );
}

export function Label({ className, ...props }: LabelHTMLAttributes<HTMLLabelElement>) {
  return <label className={cn("block text-[11px] text-zinc-400 mb-1", className)} {...props} />;
}

export function Field({ label, children, className }: { label: string; children: ReactNode; className?: string }) {
  return (
    <div className={className}>
      <Label>{label}</Label>
      {children}
    </div>
  );
}

export function ErrorPre({ children }: { children: ReactNode }) {
  return (
    <pre className="selectable m-2 rounded-md border border-red-900/60 bg-red-950/40 p-3 font-mono text-[12px] whitespace-pre-wrap text-red-300">
      {children}
    </pre>
  );
}

/** Затемнённый фон на весь экран; mousedown по фону (не по контенту) закрывает. */
export function Overlay({
  onClose,
  className,
  closeOnEsc = false,
  children,
}: {
  onClose: () => void;
  className?: string;
  closeOnEsc?: boolean;
  children: ReactNode;
}) {
  useEffect(() => {
    if (!closeOnEsc) return;
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        onClose();
      }
    };
    window.addEventListener("keydown", handleKey, true);
    return () => window.removeEventListener("keydown", handleKey, true);
  }, [closeOnEsc, onClose]);
  return (
    <div
      className={cn("fixed inset-0 z-50 flex justify-center", className)}
      onMouseDown={(e) => e.target === e.currentTarget && onClose()}
    >
      {children}
    </div>
  );
}

/** Каркас модального диалога поверх Overlay. */
export function Dialog({
  title,
  onClose,
  children,
  wide,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  wide?: boolean;
}) {
  return (
    <Overlay onClose={onClose} closeOnEsc className="items-center bg-black/60">
      <div
        className={cn(
          "max-h-[80vh] overflow-y-auto rounded-lg border border-zinc-700 bg-zinc-900 p-4 shadow-2xl",
          wide ? "w-[560px]" : "w-[420px]",
        )}
      >
        <div className="mb-3 text-[13px] font-semibold text-zinc-100">{title}</div>
        {children}
      </div>
    </Overlay>
  );
}

/** Замена window.confirm — в Tauri webview нативный confirm не блокирует. */
export function ConfirmDialog() {
  const confirm = useApp((s) => s.confirm);
  const resolveConfirm = useApp((s) => s.resolveConfirm);
  if (!confirm) return null;

  return (
    <Overlay onClose={() => resolveConfirm(false)} closeOnEsc className="items-center bg-black/60">
      <div className="w-100 rounded-lg border border-zinc-700 bg-zinc-900 p-4 shadow-2xl">
        <div className="text-[13px] font-semibold text-zinc-100">{confirm.title}</div>
        {confirm.message && (
          <div className="selectable mt-2 max-h-60 overflow-y-auto whitespace-pre-wrap text-[12px] leading-relaxed text-zinc-400">
            {confirm.message}
          </div>
        )}
        <div className="mt-4 flex justify-end gap-2">
          <Button onClick={() => resolveConfirm(false)}>Отмена</Button>
          <Button autoFocus variant={confirm.danger ? "danger" : "primary"} onClick={() => resolveConfirm(true)}>
            {confirm.confirmLabel ?? "Ок"}
          </Button>
        </div>
      </div>
    </Overlay>
  );
}
