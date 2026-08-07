import {
  Clock,
  Eye,
  FileText,
  History,
  Key,
  Link2,
  Lock,
  Pencil,
  Plus,
  Share2,
  Trash2,
  Zap,
} from "lucide-react";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import {
  SecretEntry,
  getOutCommand,
  isBinaryEntry,
  keyArgs,
  runSec,
  splitProject,
} from "../lib/sec";
import { useApp } from "../store";
import { IconButton, cn } from "./ui";

const KIND_COLOR: Record<string, string> = {
  password: "border-amber-500/40 bg-amber-500/10 text-amber-400",
  apikey: "border-sky-500/40 bg-sky-500/10 text-sky-400",
  totp: "border-emerald-500/40 bg-emerald-500/10 text-emerald-400",
  env: "border-violet-400/40 bg-violet-400/10 text-violet-400",
  config: "border-zinc-600 bg-zinc-800/60 text-zinc-400",
  file: "border-zinc-600 bg-zinc-800/60 text-zinc-400",
};

function matches(project: string, entry: SecretEntry, filter: string): boolean {
  if (!filter) return true;
  const hay = `${project} ${entry.key} ${entry.meta?.note ?? ""} ${entry.meta?.kind ?? ""}`.toLowerCase();
  return filter
    .toLowerCase()
    .split(/\s+/)
    .every((w) => hay.includes(w));
}

export function SecretList() {
  const { data, loading, loadError, filter, lastProject, openDialog } = useApp();

  if (loadError) {
    return (
      <div className="flex flex-1 flex-col items-center justify-center gap-2 text-zinc-500">
        <Lock size={28} className="text-zinc-600" />
        <div className="max-w-md whitespace-pre-wrap text-center text-[12px]">{loadError}</div>
      </div>
    );
  }
  if (!data) {
    return <div className="flex flex-1 items-center justify-center text-[12px] text-zinc-600">{loading ? "Загрузка…" : ""}</div>;
  }

  const projects = Object.keys(data).sort();
  // Проект прошлого сеанса — первой секцией. Порядок фиксируется на запуске
  // (rememberProject не трогает стейт): пока окно открыто, список не прыгает,
  // серию login+pass можно копировать с одного места.
  if (lastProject && projects.includes(lastProject)) {
    projects.splice(projects.indexOf(lastProject), 1);
    projects.unshift(lastProject);
  }

  const sections = projects
    .map((p) => ({ project: p, entries: (data[p] ?? []).filter((e) => matches(p, e, filter)) }))
    .filter((s) => s.entries.length > 0);

  if (sections.length === 0) {
    return (
      <div className="flex flex-1 flex-col items-center justify-center gap-2 text-zinc-500">
        <Lock size={28} className="text-zinc-600" />
        <div className="text-[13px]">{filter ? "Ничего не нашлось" : "Секретов нет"}</div>
        {!filter && <div className="text-[11px] text-zinc-600">Добавь первую пару — кнопкой «+» сверху или `sec set` в терминале</div>}
      </div>
    );
  }

  return (
    <div className="flex-1 overflow-y-auto pb-4">
      {sections.map(({ project, entries }) => (
        <ProjectSection key={project} project={project} entries={entries} />
      ))}
      <div className="px-4 pt-3 text-[11px] text-zinc-600">
        Клик по строке кладёт значение в буфер (через sec, приложение его не видит).
      </div>
    </div>
  );

  function ProjectSection({ project, entries }: { project: string; entries: SecretEntry[] }) {
    const { service, env } = splitProject(project);
    return (
      <section>
        <div className="group/hdr sticky top-0 z-10 flex items-center gap-2 border-b border-zinc-800 bg-zinc-925 px-4 py-1.5">
          <span className="font-mono text-[11px] font-semibold tracking-wider text-zinc-400">{service}</span>
          {env && (
            <span className="rounded border border-sky-500/40 bg-sky-500/10 px-1 py-px font-mono text-[9px] font-semibold text-sky-400">
              {env}
            </span>
          )}
          <span className="text-[10px] text-zinc-600">{entries.length}</span>
          <span className="ml-auto flex items-center gap-0.5 opacity-0 transition-opacity group-hover/hdr:opacity-100">
            <IconButton title={`Добавить секрет в «${project}»`} onClick={() => openDialog({ type: "add", project })}>
              <Plus size={12} />
            </IconButton>
            <IconButton title={`Сгенерировать секрет в «${project}»`} onClick={() => openDialog({ type: "generate", project })}>
              <Zap size={12} />
            </IconButton>
            <IconButton title="Поделиться паком (ссылка на весь проект)" onClick={() => openDialog({ type: "share", project })}>
              <Share2 size={12} />
            </IconButton>
          </span>
        </div>
        {entries.map((entry) => (
          <SecretRow key={entry.key} project={project} entry={entry} />
        ))}
      </section>
    );
  }
}

function SecretRow({ project, entry }: { project: string; entry: SecretEntry }) {
  const { openDialog, showToast, rememberProject, refresh, askConfirm } = useApp();
  const ref = `${project}/${entry.key}`;
  const kind = entry.meta?.kind;
  const isTotp = kind === "totp";
  const isBinary = isBinaryEntry(entry);

  const copyValue = async (extra: string[] = []) => {
    try {
      if (isBinary) {
        // бинарный (файловый) секрет в буфер не отдаётся — даём готовую команду
        await writeText(getOutCommand(project, entry.key));
        showToast(`${ref} — бинарный: команда выгрузки в буфере`, "info");
      } else if (isTotp) {
        await runSec(keyArgs("otp", project, entry.key, "--clip"));
        showToast(`TOTP ${ref} — в буфере`, "success");
      } else {
        await runSec(keyArgs("get", project, entry.key, "--clip", ...extra));
        showToast(`${ref} — в буфере (значение не показано)`, "success");
      }
      rememberProject(project);
    } catch (err) {
      showToast(String(err));
    }
  };

  const peek = async () => {
    try {
      const out = await runSec(keyArgs("get", project, entry.key, "--peek"));
      showToast(`${ref}: ${out.trim()}`, "info");
    } catch (err) {
      showToast(String(err));
    }
  };

  const remove = async () => {
    const ok = await askConfirm({
      title: `Удалить ${ref}?`,
      message: "Ключ будет удалён из хранилища sec.",
      confirmLabel: "Удалить",
      danger: true,
    });
    if (!ok) return;
    try {
      const out = await runSec(keyArgs("rm", project, entry.key));
      showToast(out.trim() || `${ref} удалён`, "success");
      refresh();
    } catch (err) {
      showToast(String(err));
    }
  };

  return (
    <div
      className="group flex h-8 cursor-default items-center gap-2 border-b border-zinc-900 px-4 hover:bg-zinc-900"
      onClick={() => copyValue()}
      title={isBinary ? "Клик — скопировать команду выгрузки" : "Клик — скопировать значение в буфер"}
    >
      {isBinary ? (
        <FileText size={13} className="shrink-0 text-zinc-500" />
      ) : isTotp ? (
        <Clock size={13} className="shrink-0 text-emerald-500" />
      ) : (
        <Key size={13} className="shrink-0 text-zinc-500" />
      )}
      <span className="shrink-0 font-mono text-[12px] text-zinc-100">{entry.key}</span>
      {entry.ref && (
        <span title={`ссылка на ${entry.ref}`}>
          <Link2 size={11} className="shrink-0 text-sky-500" />
        </span>
      )}
      {entry.meta?.note && <span className="truncate text-[11px] text-zinc-500">{entry.meta.note}</span>}

      <span className="ml-auto flex shrink-0 items-center gap-2">
        <span className="flex items-center gap-0.5 opacity-0 transition-opacity group-hover:opacity-100" onClick={(e) => e.stopPropagation()}>
          {!isBinary && !isTotp && (
            <IconButton title="Скопировать с очисткой буфера через 60с" onClick={() => copyValue(["--clear-after", "60s"])}>
              <Clock size={12} />
            </IconButton>
          )}
          <IconButton title="Маска значения (peek)" onClick={peek}>
            <Eye size={12} />
          </IconButton>
          <IconButton title="Поделиться ссылкой" onClick={() => openDialog({ type: "share", project, key: entry.key })}>
            <Share2 size={12} />
          </IconButton>
          <IconButton title="Редактировать" onClick={() => openDialog({ type: "edit", project, entry })}>
            <Pencil size={12} />
          </IconButton>
          <IconButton title="История версий" onClick={() => openDialog({ type: "history", project, entry })}>
            <History size={12} />
          </IconButton>
          <IconButton title="Удалить" className="hover:text-red-400" onClick={remove}>
            <Trash2 size={12} />
          </IconButton>
        </span>
        {kind && (
          <span className={cn("rounded border px-1 py-px text-[9px] font-semibold", KIND_COLOR[kind] ?? "border-zinc-600 text-zinc-400")}>
            {kind}
          </span>
        )}
        {entry.history > 0 && (
          <span className="text-[10px] text-zinc-600" title="версий в истории">
            +{entry.history}
          </span>
        )}
        <span className="w-14 text-right text-[10px] text-zinc-600">
          {isBinary ? `${entry.chars} Б` : `${entry.chars} симв.`}
        </span>
        <span className="w-16 text-right text-[10px] text-zinc-600" title={`обновлён ${entry.updatedAt}`}>
          {new Date(entry.updatedAt).toLocaleDateString("ru-RU", { day: "2-digit", month: "2-digit", year: "2-digit" })}
        </span>
      </span>
    </div>
  );
}
