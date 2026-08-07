// «Что нового» после обновления приложения.
//
// Триггер — версия изменилась с прошлого запуска. Содержимое — последние
// релизы из публичного GitHub API (минимум HISTORY штук; всё невиданное
// помечается fresh). Оффлайн-фолбэк: заметки, которые апдейтер отложил
// перед перезапуском ({version, notes} в localStorage, см. updater.ts).
import { getVersion } from "@tauri-apps/api/app";

const PENDING_KEY = "sec.pendingWhatsNew";
const SEEN_KEY = "sec.lastSeenVersion";
/** owner/repo — тот же проект, куда смотрит endpoint апдейтера. */
const GITHUB_REPO = "Kaidstor/sec";
// В монорепо две линейки тегов: v* — CLI (goreleaser), app-v* — приложение.
// Здесь нужны только релизы приложения.
const TAG_PREFIX = "app-v";

/** Страница релизов — для перехода «Все релизы» из диалога. */
export const RELEASES_PAGE_URL = `https://github.com/${GITHUB_REPO}/releases`;

/** Сколько версий диалог показывает, даже если новых меньше. */
const HISTORY = 3;

export interface ReleaseNote {
  version: string;
  notes: string;
  /** Вышла позже версии, с которой пользователь запускался в прошлый раз. */
  fresh?: boolean;
}

/** Откладывает заметки устанавливаемого обновления до перезапуска. */
export function stashPendingNotes(version: string, notes?: string) {
  try {
    localStorage.setItem(PENDING_KEY, JSON.stringify({ version, notes: notes ?? "" }));
  } catch {
    // best-effort
  }
}

/** "1.2.3" → почленное числовое сравнение; пререлизы не используются. */
const cmp = (a: string, b: string): number => {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d) return d;
  }
  return 0;
};

/** Релизы приложения ≤ текущей версии из GitHub, новые сверху. */
async function loadReleases(current: string): Promise<ReleaseNote[]> {
  const res = await fetch(`https://api.github.com/repos/${GITHUB_REPO}/releases?per_page=30`, {
    headers: { Accept: "application/vnd.github+json" },
  });
  if (!res.ok) return [];
  const releases: { tag_name: string; body?: string }[] = await res.json();
  return releases
    .filter((r) => r.tag_name.startsWith(TAG_PREFIX))
    .map((r) => ({
      version: r.tag_name.slice(TAG_PREFIX.length),
      notes: r.body ?? "",
    }))
    .filter((r) => cmp(r.version, current) <= 0)
    .sort((a, b) => cmp(b.version, a.version));
}

/**
 * Релизы для диалога «Что нового» (пусто — не показывать). Звать один раз
 * на старте: помечает текущую версию как просмотренную.
 */
export async function collectWhatsNew(): Promise<ReleaseNote[]> {
  try {
    const current = await getVersion();
    const seen = localStorage.getItem(SEEN_KEY);
    localStorage.setItem(SEEN_KEY, current);

    let pending: ReleaseNote | null = null;
    const raw = localStorage.getItem(PENDING_KEY);
    if (raw) {
      localStorage.removeItem(PENDING_KEY);
      pending = JSON.parse(raw) as ReleaseNote;
    }

    // Первый запуск (свежая установка) — рассказывать нечего.
    if (!seen || seen === current) return [];

    const history = await loadReleases(current).catch(() => []);
    if (history.length > 0) {
      const isFresh = (v: string) => cmp(v, seen) > 0;
      const freshCount = history.filter((r) => isFresh(r.version)).length;
      return history
        .slice(0, Math.max(HISTORY, freshCount))
        .map((r) => ({ ...r, fresh: isFresh(r.version) }));
    }

    // Оффлайн: хотя бы отложенные заметки только что установленной версии.
    if (pending && pending.version === current && pending.notes.trim()) {
      return [{ ...pending, fresh: true }];
    }
    return [];
  } catch {
    return [];
  }
}
