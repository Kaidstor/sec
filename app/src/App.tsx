import { invoke } from "@tauri-apps/api/core";
import { Link2, Plus, Search, Settings, Zap } from "lucide-react";
import { useEffect } from "react";
import { SecretList } from "./components/SecretList";
import { AddSecretDialog, EditSecretDialog, GenerateSecretDialog } from "./components/dialogs/forms";
import { HistoryDialog, LinksDialog, SettingsDialog, ShareDialog } from "./components/dialogs/panels";
import { ConfirmDialog, IconButton, RefreshButton, cn } from "./components/ui";
import { isKey } from "./lib/keys";
import { isMac } from "./lib/platform";
import { plural } from "./lib/plural";
import { dragWindow, onWindowFocus } from "./lib/window";
import { useApp } from "./store";

export default function App() {
  const { refresh, loading, filter, setFilter, toast, dialog, openDialog } = useApp();

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // Стор могли поменять из CLI, пока окно было в фоне.
  useEffect(() => onWindowFocus(() => void refresh()), [refresh]);

  // Окно создано скрытым (visible: false) — показываем после первого
  // отрисованного кадра, чтобы не было «растягивания» геометрии на старте.
  useEffect(() => {
    const outer = requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        // Фокус ставим только после показа окна: скрытый вебвью его не удержит.
        void invoke("reveal_main_window")
          .catch(() => {})
          .finally(() => document.getElementById("search")?.focus());
      });
    });
    return () => cancelAnimationFrame(outer);
  }, []);

  // ⌘F/⌘K — в поиск, ⌘N — новый секрет, ⌘R — обновить, ⌘, — настройки
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const mod = isMac ? e.metaKey : e.ctrlKey;
      if (!mod) return;
      if (isKey(e, "f") || isKey(e, "k")) {
        e.preventDefault();
        document.getElementById("search")?.focus();
      } else if (isKey(e, "n")) {
        e.preventDefault();
        openDialog({ type: "add" });
      } else if (isKey(e, "r")) {
        e.preventDefault();
        void refresh();
      } else if (e.key === "," || e.code === "Comma") {
        e.preventDefault();
        openDialog({ type: "settings" });
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [openDialog, refresh]);

  return (
    <div className="flex h-full flex-col bg-zinc-950 text-[13px] text-zinc-100 antialiased">
      <header
        onMouseDown={dragWindow}
        className={cn(
          "flex h-10 shrink-0 items-center gap-2 border-b border-zinc-800 bg-zinc-925 pr-3",
          isMac ? "pl-24" : "pl-4",
        )}
      >
        <span className="font-mono text-[15px] font-extrabold tracking-tight text-zinc-100">
          sec<span className="text-sky-500">.</span>
        </span>
        <div className="relative ml-2 w-72 max-w-full">
          <Search size={12} className="pointer-events-none absolute left-2 top-1/2 -translate-y-1/2 text-zinc-600" />
          <input
            id="search"
            spellCheck={false}
            autoCorrect="off"
            autoCapitalize="off"
            placeholder="Проект или ключ…  (⌘F)"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            onKeyDown={(e) => e.key === "Escape" && setFilter("")}
            className={cn(
              "h-6 w-full rounded-md border border-zinc-800 bg-zinc-900 pl-6 pr-2 text-[12px]",
              "text-zinc-100 placeholder:text-zinc-600 focus:border-sky-600 focus:outline-none",
            )}
          />
        </div>
        <span className="ml-auto flex items-center gap-0.5">
          <RefreshButton loading={loading} onClick={() => void refresh()} />
          <IconButton title="Добавить секрет (⌘N)" onClick={() => openDialog({ type: "add" })}>
            <Plus size={14} />
          </IconButton>
          <IconButton title="Сгенерировать секрет" onClick={() => openDialog({ type: "generate" })}>
            <Zap size={13} />
          </IconButton>
          <IconButton title="Активные share-ссылки" onClick={() => openDialog({ type: "links" })}>
            <Link2 size={13} />
          </IconButton>
        </span>
      </header>

      <main className="flex min-h-0 flex-1 flex-col">
        <SecretList />
      </main>

      <footer className="flex h-6 shrink-0 items-center gap-3 border-t border-zinc-800 bg-zinc-925 px-1.5 text-[11px] text-zinc-500">
        <Counts />
        {toast && (
          <span
            className={cn(
              "ml-auto max-w-[70%] truncate pr-1.5",
              toast.kind === "error" ? "text-red-400" : toast.kind === "success" ? "text-emerald-400" : "text-zinc-300",
            )}
            title={toast.message}
          >
            {toast.message.split("\n")[0]}
          </span>
        )}
        <button
          title="Настройки (⌘,)"
          onClick={() => openDialog({ type: "settings" })}
          className={cn("flex items-center gap-1 rounded px-1.5 py-0.5 transition-colors hover:bg-zinc-800/80 hover:text-zinc-300", !toast && "ml-auto")}
        >
          <Settings size={11} />
        </button>
      </footer>

      {dialog?.type === "add" && <AddSecretDialog initialProject={dialog.project} />}
      {dialog?.type === "generate" && <GenerateSecretDialog initialProject={dialog.project} />}
      {dialog?.type === "edit" && <EditSecretDialog project={dialog.project} entry={dialog.entry} />}
      {dialog?.type === "history" && <HistoryDialog project={dialog.project} entry={dialog.entry} />}
      {dialog?.type === "share" && <ShareDialog project={dialog.project} secretKey={dialog.key} />}
      {dialog?.type === "links" && <LinksDialog />}
      {dialog?.type === "settings" && <SettingsDialog />}
      <ConfirmDialog />
    </div>
  );
}

function Counts() {
  const data = useApp((s) => s.data);
  if (!data) return <span>sec</span>;
  const projects = Object.keys(data).length;
  const keys = Object.values(data).reduce((n, arr) => n + arr.length, 0);
  return (
    <span>
      {projects} {plural(projects, ["проект", "проекта", "проектов"])} · {keys}{" "}
      {plural(keys, ["ключ", "ключа", "ключей"])}
    </span>
  );
}
