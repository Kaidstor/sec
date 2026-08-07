import { Check, Download, RotateCw, TriangleAlert, X } from "lucide-react";
import { useEffect, useState } from "react";
import { useUpdater } from "../lib/updater";
import { cn } from "./ui";

/**
 * Плавающая плашка (слева внизу) о новой версии. Два шага:
 * «Обновить до vX» → загрузка (%) → «Перезапустить». Крестик прячет её,
 * но шаг перезапуска всплывает снова, даже если предложение закрывали.
 * Ручная проверка из настроек тоже получает здесь короткий отклик,
 * когда ставить нечего («Версия актуальна» / проверка не удалась).
 */
export function UpdateToast() {
  const { update, downloading, progress, ready, error, manualCheck, install, restart } = useUpdater();
  const [dismissed, setDismissed] = useState(false);

  useEffect(() => {
    if (ready) setDismissed(false);
  }, [ready]);

  // Ручная проверка, нашедшая обновление, возвращает скрытую плашку;
  // «актуально» и ошибка гаснут сами через несколько секунд.
  useEffect(() => {
    if (!manualCheck) return;
    if (manualCheck.status === "found") {
      setDismissed(false);
      return;
    }
    const t = setTimeout(() => useUpdater.setState({ manualCheck: null }), 4000);
    return () => clearTimeout(t);
  }, [manualCheck]);

  if (manualCheck && manualCheck.status !== "found") {
    const failed = manualCheck.status === "error";
    return (
      <div
        className={cn(
          "fixed bottom-8 left-2 z-50 flex items-center gap-1.5 rounded-lg px-3 py-1.5",
          "text-[12px] font-medium shadow-lg ring-1 ring-inset",
          failed
            ? "bg-red-950 text-red-200 shadow-red-950/40 ring-red-500/30"
            : "bg-zinc-800 text-zinc-200 shadow-black/40 ring-white/10",
        )}
        title={failed ? manualCheck.message : undefined}
      >
        {failed ? <TriangleAlert size={13} /> : <Check size={13} />}
        {failed ? "Не удалось проверить обновления" : "Версия актуальна"}
      </div>
    );
  }

  if (!update || dismissed) return null;

  const handleAction = () => {
    if (ready) void restart();
    else if (!downloading) void install();
  };

  const label = ready ? (
    "Перезапустить"
  ) : downloading ? (
    <>
      Загрузка…
      <span className="w-[4ch] text-left tabular-nums">{progress ?? 0}%</span>
    </>
  ) : (
    `Обновить до v${update.version}`
  );
  const Icon = ready ? RotateCw : Download;

  return (
    <div
      className={cn(
        "fixed bottom-8 left-2 z-50 flex items-stretch overflow-hidden rounded-lg",
        "bg-sky-600 text-[12px] font-medium text-white",
        "shadow-lg shadow-sky-950/40 ring-1 ring-inset ring-white/15",
      )}
    >
      <button
        onClick={handleAction}
        disabled={downloading}
        title={
          error
            ? `Обновление не удалось: ${error}`
            : ready
              ? "Перезапустить и применить обновление"
              : `Скачать v${update.version} и обновиться`
        }
        className={cn(
          "flex items-center gap-1.5 py-1.5 pr-3 pl-3 transition-colors",
          "hover:bg-sky-500 disabled:cursor-default disabled:opacity-90",
        )}
      >
        <Icon size={13} className={downloading ? "animate-pulse" : undefined} />
        {label}
      </button>
      <div className="w-px bg-white/20" />
      <button
        onClick={() => setDismissed(true)}
        title="Скрыть"
        className="flex items-center px-2 text-white/80 transition-colors hover:bg-sky-500 hover:text-white"
      >
        <X size={13} />
      </button>
    </div>
  );
}
