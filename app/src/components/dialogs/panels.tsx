import { getVersion } from "@tauri-apps/api/app";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { ArrowDown, ArrowUp, Check, CheckCircle2, Copy, Redo2, Undo2, X } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import {
  HistoryVersion,
  SecretEntry,
  ShareLink,
  ShareResult,
  TTL_OPTIONS,
  isBinaryEntry,
  keyArgs,
  keyHistory,
  runSec,
  shareKey,
  shareLinks,
  sharePack,
  splitProject,
} from "../../lib/sec";
import { THEMES, Theme } from "../../lib/themes";
import { useUpdater } from "../../lib/updater";
import { useApp } from "../../store";
import { Button, Dialog, Field, Select, cn } from "../ui";

export function HistoryDialog({ project, entry }: { project: string; entry: SecretEntry }) {
  const { openDialog, showToast, refresh } = useApp();
  const ref = `${project}/${entry.key}`;
  const [versions, setVersions] = useState<HistoryVersion[] | null>(null);
  const close = () => openDialog(null);

  const load = useCallback(() => {
    keyHistory(project, entry.key)
      .then(setVersions)
      .catch((err) => showToast(String(err)));
  }, [project, entry.key, showToast]);
  useEffect(load, [load]);

  const step = async (cmd: "undo" | "redo") => {
    try {
      await runSec(keyArgs(cmd, project, entry.key));
      showToast(`${cmd} — готово (${ref})`, "success");
      load();
      refresh();
    } catch (err) {
      showToast(String(err));
    }
  };

  const posTitle = (v: HistoryVersion) =>
    v.pos === 0 ? "текущее" : v.pos > 0 ? `+${v.pos} (отменено, redo вернёт)` : String(v.pos);

  return (
    <Dialog title={`История ${ref}`} onClose={close} wide>
      <div className="flex flex-col gap-1">
        {(versions ?? []).map((v) => (
          <div key={v.pos} className="flex items-center gap-2 rounded-md border border-zinc-800 bg-zinc-925 px-2.5 py-1.5">
            {v.pos === 0 ? (
              <CheckCircle2 size={13} className="shrink-0 text-emerald-500" />
            ) : v.pos > 0 ? (
              <ArrowUp size={13} className="shrink-0 text-zinc-500" />
            ) : (
              <ArrowDown size={13} className="shrink-0 text-zinc-500" />
            )}
            <span className="text-[12px] text-zinc-200">{posTitle(v)}</span>
            <button
              className="selectable ml-auto cursor-pointer font-mono text-[11px] text-zinc-500 hover:text-zinc-300"
              title="Скопировать отпечаток (безопасен для чата)"
              onClick={() => writeText(v.fingerprint).then(() => showToast("Отпечаток в буфере", "info"))}
            >
              {v.fingerprint}
            </button>
            <span className="w-14 text-right text-[10px] text-zinc-600">{v.chars} симв.</span>
            <span className="w-24 text-right text-[10px] text-zinc-600">
              {new Date(v.updatedAt).toLocaleString("ru-RU", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" })}
            </span>
          </div>
        ))}
        {versions?.length === 0 && <div className="text-[12px] text-zinc-500">Истории нет — только текущее значение.</div>}
        <div className="mt-3 flex justify-end gap-2">
          <Button onClick={() => step("undo")}>
            <Undo2 size={13} /> Undo
          </Button>
          <Button onClick={() => step("redo")}>
            <Redo2 size={13} /> Redo
          </Button>
          <Button variant="primary" onClick={close}>
            Готово
          </Button>
        </div>
      </div>
    </Dialog>
  );
}

// Один диалог на оба вида ссылок: key задан — одиночный секрет, нет — пак
// проекта (все ключи или выбранные, --all/--only).
export function ShareDialog({ project, secretKey }: { project: string; secretKey?: string }) {
  const { data, openDialog, showToast } = useApp();
  const entries = data?.[project] ?? [];
  const [selected, setSelected] = useState<Set<string>>(() => new Set(entries.map((e) => e.key)));
  const [ttl, setTtl] = useState("24h");
  const [multi, setMulti] = useState(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<ShareResult | null>(null);
  const close = () => openDialog(null);
  const { service, env } = splitProject(project);
  const target = secretKey ? `${service}/${secretKey}${env ? ` -e ${env}` : ""}` : `${service}${env ? ` -e ${env}` : ""} (пак)`;

  const toggle = (k: string) =>
    setSelected((s) => {
      const next = new Set(s);
      if (next.has(k)) next.delete(k);
      else next.add(k);
      return next;
    });

  const create = async () => {
    setBusy(true);
    try {
      let res: ShareResult;
      if (secretKey) {
        res = await shareKey(project, secretKey, ttl, multi);
      } else {
        if (selected.size === 0) {
          showToast("Выбери хотя бы один ключ");
          setBusy(false);
          return;
        }
        const keys = selected.size === entries.length ? null : [...selected];
        res = await sharePack(project, keys, ttl, multi);
      }
      setResult(res);
      await writeText(res.url);
    } catch (err) {
      showToast(String(err));
    } finally {
      setBusy(false);
    }
  };

  if (result) {
    return (
      <Dialog title="Ссылка создана" onClose={close} wide>
        <div className="flex flex-col gap-3">
          <div className="selectable break-all rounded-md border border-zinc-700 bg-zinc-925 p-2.5 font-mono text-[12px] text-sky-400">
            {result.url}
          </div>
          <div className="text-[11px] text-zinc-500">{result.note || "Ссылка скопирована в буфер."} Скопирована в буфер.</div>
          <div className="text-[11px] text-zinc-600">
            URL печатать можно — это цель передачи; значение зашифровано локально, сервер видит только шифротекст, ключ расшифровки — во
            фрагменте после #.
          </div>
          <div className="flex justify-end gap-2">
            <Button onClick={() => writeText(result.url).then(() => showToast("Ссылка в буфере", "info"))}>
              <Copy size={13} /> Скопировать ещё раз
            </Button>
            <Button variant="primary" onClick={close}>
              Готово
            </Button>
          </div>
        </div>
      </Dialog>
    );
  }

  return (
    <Dialog title={`Поделиться: ${target}`} onClose={close}>
      <div className="flex flex-col gap-3">
        {!secretKey && (
          <div className="max-h-48 overflow-y-auto rounded-md border border-zinc-800">
            {entries.map((e) => (
              <label key={e.key} className="flex cursor-pointer items-center gap-2 border-b border-zinc-900 px-2.5 py-1 text-[12px] last:border-0 hover:bg-zinc-900">
                <input type="checkbox" checked={selected.has(e.key)} onChange={() => toggle(e.key)} />
                <span className="font-mono text-zinc-200">{e.key}</span>
                {isBinaryEntry(e) && <span className="text-[10px] text-zinc-500">файл</span>}
                {e.meta?.kind === "file" && !isBinaryEntry(e) && <span className="text-[10px] text-zinc-500">файл</span>}
              </label>
            ))}
          </div>
        )}
        <div className="flex items-end gap-3">
          <Field label="Срок жизни" className="w-28">
            <Select className="w-full" value={ttl} onChange={(e) => setTtl(e.target.value)}>
              {TTL_OPTIONS.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </Select>
          </Field>
          <label className="flex items-center gap-1.5 pb-1 text-[12px] text-zinc-300" title="Умолчание — одноразовая: сгорает при первом открытии">
            <input type="checkbox" checked={multi} onChange={(e) => setMulti(e.target.checked)} /> многоразовая
          </label>
        </div>
        <div className="text-[11px] text-zinc-600">
          {secretKey
            ? "Одноразовая ссылка сгорает при первом открытии или по TTL — что раньше."
            : "Получатель увидит список ключей, скачает готовый .env, файловые ключи — отдельными файлами."}
        </div>
        <div className="flex justify-end gap-2">
          <Button onClick={close}>Отмена</Button>
          <Button variant="primary" disabled={busy} onClick={create}>
            Создать ссылку
          </Button>
        </div>
      </div>
    </Dialog>
  );
}

export function LinksDialog() {
  const { openDialog, showToast, askConfirm } = useApp();
  const [links, setLinks] = useState<ShareLink[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const close = () => openDialog(null);

  const load = useCallback(() => {
    shareLinks()
      .then((l) => {
        setLinks(l);
        setError(null);
      })
      .catch((err) => setError(String(err)));
  }, []);
  useEffect(load, [load]);

  const revoke = async (id: string) => {
    const ok = await askConfirm({ title: `Отозвать ссылку ${id}?`, confirmLabel: "Отозвать", danger: true });
    if (!ok) return;
    try {
      await runSec(["share", "revoke", id]);
      showToast(`Ссылка ${id} отозвана`, "success");
      load();
    } catch (err) {
      showToast(String(err));
    }
  };

  const fmt = (s: string) =>
    new Date(s).toLocaleString("ru-RU", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" });

  return (
    <Dialog title="Активные ссылки" onClose={close} wide>
      <div className="flex flex-col gap-1">
        {error && <div className="selectable whitespace-pre-wrap text-[12px] text-red-400">{error}</div>}
        {links?.length === 0 && <div className="text-[12px] text-zinc-500">Активных ссылок нет.</div>}
        {(links ?? []).map((l) => (
          <div key={l.id} className="flex items-center gap-2 rounded-md border border-zinc-800 bg-zinc-925 px-2.5 py-1.5">
            <span className="selectable font-mono text-[11px] text-zinc-300">{l.id}</span>
            <span className={cn("rounded border px-1 py-px text-[9px] font-semibold", l.once ? "border-amber-500/40 bg-amber-500/10 text-amber-400" : "border-sky-500/40 bg-sky-500/10 text-sky-400")}>
              {l.once ? "once" : "multi"}
            </span>
            <span className="ml-auto text-[10px] text-zinc-600">до {fmt(l.expiresAt)}</span>
            <span className="text-[10px] text-zinc-600">просмотров: {l.claims}</span>
            <Button className="text-red-400 hover:bg-red-950/40" onClick={() => revoke(l.id)}>
              <X size={12} /> Отозвать
            </Button>
          </div>
        ))}
        <div className="mt-2 text-[11px] text-zinc-600">
          URL восстановить нельзя — ключ расшифровки существовал только в момент создания.
        </div>
        <div className="mt-2 flex justify-end">
          <Button variant="primary" onClick={close}>
            Готово
          </Button>
        </div>
      </div>
    </Dialog>
  );
}

function ThemeCard({ theme, active, onPick }: { theme: Theme; active: boolean; onPick: () => void }) {
  return (
    <button
      onClick={onPick}
      className={cn(
        "flex flex-col gap-1.5 rounded-md border p-2 text-left transition-colors",
        active ? "border-sky-600 bg-zinc-800/40" : "border-zinc-700 hover:border-zinc-600 hover:bg-zinc-800/30",
      )}
    >
      <span className="flex h-10 w-full items-center gap-1.5 rounded border border-black/20 px-2" style={{ background: theme.preview.bg }}>
        <span className="size-2.5 shrink-0 rounded-full" style={{ background: theme.preview.accent }} />
        <span className="h-1.5 flex-1 rounded-sm" style={{ background: theme.preview.panel }} />
        <span className="h-1.5 w-8 rounded-sm opacity-80" style={{ background: theme.preview.text }} />
      </span>
      <span className="flex items-center gap-1 text-[12px] text-zinc-200">
        {theme.label}
        {active && <Check size={12} className="ml-auto text-sky-400" />}
      </span>
    </button>
  );
}

export function SettingsDialog() {
  const { openDialog, themeId, setTheme } = useApp();
  const { checking, checkForUpdates } = useUpdater();
  const [version, setVersion] = useState("");
  const [appVersion, setAppVersion] = useState("");
  const close = () => openDialog(null);

  useEffect(() => {
    runSec(["version"])
      .then((v) => setVersion(v.trim()))
      .catch((err) => setVersion(String(err)));
    getVersion()
      .then(setAppVersion)
      .catch(() => {});
  }, []);

  return (
    <Dialog title="Настройки" onClose={close}>
      <div className="flex flex-col gap-3">
        <div>
          <div className="mb-1.5 text-[11px] font-semibold tracking-wider text-zinc-500">ТЕМА</div>
          <div className="grid grid-cols-2 gap-2">
            {THEMES.map((t) => (
              <ThemeCard key={t.id} theme={t} active={t.id === themeId} onPick={() => setTheme(t.id)} />
            ))}
          </div>
        </div>
        <div>
          <div className="mb-1.5 text-[11px] font-semibold tracking-wider text-zinc-500">ВЕРСИИ</div>
          <div className="flex items-center justify-between gap-2">
            <div className="selectable font-mono text-[11px] text-zinc-400">
              {appVersion && <div>app {appVersion}</div>}
              <div>{version || "…"}</div>
            </div>
            <Button disabled={checking} onClick={() => void checkForUpdates(true)}>
              {checking ? "Проверка…" : "Проверить обновления"}
            </Button>
          </div>
        </div>
        <div className="flex justify-end">
          <Button variant="primary" onClick={close}>
            Готово
          </Button>
        </div>
      </div>
    </Dialog>
  );
}
