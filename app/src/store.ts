import { create } from "zustand";
import { applyTheme, cachedThemeId } from "./lib/themes";
import { SecretEntry, SecretStore, listSecrets } from "./lib/sec";

export type Toast = { message: string; kind: "info" | "success" | "error" };

export type Dialog =
  | { type: "add"; project?: string }
  | { type: "generate"; project?: string }
  | { type: "edit"; project: string; entry: SecretEntry }
  | { type: "history"; project: string; entry: SecretEntry }
  | { type: "share"; project: string; key?: string }
  | { type: "links" }
  | { type: "settings" }
  | null;

interface ConfirmState {
  title: string;
  message?: string;
  confirmLabel?: string;
  danger?: boolean;
  resolve: (ok: boolean) => void;
}

interface AppState {
  data: SecretStore | null;
  loading: boolean;
  loadError: string | null;
  filter: string;
  lastProject: string | null;
  toast: Toast | null;
  dialog: Dialog;
  confirm: ConfirmState | null;
  themeId: string;

  refresh: () => Promise<void>;
  setFilter: (v: string) => void;
  rememberProject: (p: string) => void;
  showToast: (message: string, kind?: Toast["kind"]) => void;
  openDialog: (d: Dialog) => void;
  askConfirm: (opts: Omit<ConfirmState, "resolve">) => Promise<boolean>;
  resolveConfirm: (ok: boolean) => void;
  setTheme: (id: string) => void;
}

let toastTimer: ReturnType<typeof setTimeout> | undefined;
const LAST_PROJECT_KEY = "sec.lastProject";

export const useApp = create<AppState>((set, get) => ({
  data: null,
  loading: false,
  loadError: null,
  filter: "",
  lastProject: localStorage.getItem(LAST_PROJECT_KEY),
  toast: null,
  dialog: null,
  confirm: null,
  themeId: cachedThemeId(),

  refresh: async () => {
    set({ loading: true });
    try {
      const data = await listSecrets();
      set({ data, loading: false, loadError: null });
    } catch (err) {
      set({ loading: false, loadError: String(err) });
    }
  },

  setFilter: (v) => set({ filter: v }),

  rememberProject: (p) => {
    localStorage.setItem(LAST_PROJECT_KEY, p);
    set({ lastProject: p });
  },

  showToast: (message, kind = "error") => {
    set({ toast: { message, kind } });
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(() => set({ toast: null }), 6000);
  },

  openDialog: (d) => set({ dialog: d }),

  askConfirm: (opts) =>
    new Promise<boolean>((resolve) => {
      set({ confirm: { ...opts, resolve } });
    }),

  resolveConfirm: (ok) => {
    get().confirm?.resolve(ok);
    set({ confirm: null });
  },

  setTheme: (id) => {
    applyTheme(id);
    set({ themeId: id });
  },
}));
