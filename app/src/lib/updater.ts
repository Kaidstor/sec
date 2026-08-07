import { invoke } from "@tauri-apps/api/core";
import { check, type Update } from "@tauri-apps/plugin-updater";
import { create } from "zustand";
import { stashPendingNotes } from "./whatsNew";

/** Итог явной проверки «Проверить обновления» — для отклика в тосте. */
export type ManualCheckResult =
  | { status: "found" }
  | { status: "upToDate" }
  | { status: "error"; message: string };

type UpdaterStore = {
  checking: boolean;
  /** Доступное обновление; null — актуальная версия (или ещё не проверяли). */
  update: Update | null;
  downloading: boolean;
  /** Прогресс загрузки 0–100, null пока общий размер неизвестен. */
  progress: number | null;
  /** Обновление скачано и установлено — ждёт перезапуска. */
  ready: boolean;
  error: string | null;
  manualCheck: ManualCheckResult | null;
  checkForUpdates: (manual?: boolean) => Promise<void>;
  /** Скачать и установить (без перезапуска — выставляет `ready`). */
  install: () => Promise<void>;
  /** Перезапуск для применения установленного обновления. */
  restart: () => Promise<void>;
};

let lastCheckTime = 0;
const CHECK_INTERVAL = 60 * 60 * 1000; // повторная проверка по фокусу окна не чаще раза в час

export const useUpdater = create<UpdaterStore>((set, get) => ({
  checking: false,
  update: null,
  downloading: false,
  progress: null,
  ready: false,
  error: null,
  manualCheck: null,

  checkForUpdates: async (manual = false) => {
    if (get().checking || get().downloading) return;
    lastCheckTime = Date.now();
    set({ checking: true, error: null, manualCheck: null });
    try {
      const update = await check();
      set({
        checking: false,
        update,
        manualCheck: manual ? { status: update ? "found" : "upToDate" } : null,
      });
    } catch (e) {
      // Ожидаемо в dev и до первого опубликованного релиза — молчим,
      // если пользователь не запускал проверку сам.
      set({
        checking: false,
        update: null,
        error: String(e),
        manualCheck: manual ? { status: "error", message: String(e) } : null,
      });
    }
  },

  install: async () => {
    const { update, downloading, ready } = get();
    if (!update || downloading || ready) return;
    set({ downloading: true, progress: null, error: null });
    try {
      let total: number | undefined;
      let received = 0;
      await update.downloadAndInstall((event) => {
        switch (event.event) {
          case "Started":
            total = event.data.contentLength;
            break;
          case "Progress":
            received += event.data.chunkLength;
            if (total) {
              set({ progress: Math.min(100, Math.round((received / total) * 100)) });
            }
            break;
          case "Finished":
            set({ progress: 100 });
            break;
        }
      });
      // Установлено — ждём явного перезапуска. Заметки переживают его:
      // их покажет WhatsNewDialog.
      stashPendingNotes(update.version, update.body);
      set({ downloading: false, ready: true, progress: 100 });
    } catch (e) {
      set({ downloading: false, progress: null, error: String(e) });
    }
  },

  restart: async () => {
    try {
      // Нативная команда вместо relaunch() из plugin-process: тот запускает
      // процесс мимо LaunchServices, и на macOS новое окно стартует позади других.
      await invoke("relaunch_app");
    } catch (e) {
      set({ error: String(e) });
    }
  },
}));

/** Проверить сразу и перепроверять по фокусу окна (не чаще раза в час). */
export function initUpdater(): () => void {
  const handleFocus = () => {
    if (Date.now() - lastCheckTime > CHECK_INTERVAL) {
      void useUpdater.getState().checkForUpdates();
    }
  };
  handleFocus();
  window.addEventListener("focus", handleFocus);
  return () => window.removeEventListener("focus", handleFocus);
}
