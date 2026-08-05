import { useState } from "react";
import { KEY_RE, PROJ_RE, KINDS, SecretEntry, dupeHint, keyArgs, runSec, runSecFull, splitProject } from "../../lib/sec";
import { useApp } from "../../store";
import { Button, Dialog, Field, Input, Select } from "../ui";

function ProjectInput({
  value,
  onChange,
  projects,
}: {
  value: string;
  onChange: (v: string) => void;
  projects: string[];
}) {
  return (
    <>
      <Input list="sec-projects" placeholder="проект (например whois или bot@prod)" value={value} onChange={(e) => onChange(e.target.value)} />
      <datalist id="sec-projects">
        {projects.map((p) => (
          <option key={p} value={p} />
        ))}
      </datalist>
    </>
  );
}

export function AddSecretDialog({ initialProject }: { initialProject?: string }) {
  const { data, openDialog, showToast, rememberProject, refresh } = useApp();
  const projects = Object.keys(data ?? {}).sort();
  const [project, setProject] = useState(initialProject ?? "");
  const [key, setKey] = useState("");
  const [value, setValue] = useState("");
  const [valueRepeat, setValueRepeat] = useState("");
  const [note, setNote] = useState("");
  const [kind, setKind] = useState("");
  const [busy, setBusy] = useState(false);
  const close = () => openDialog(null);

  const submit = async () => {
    const proj = project.trim();
    const k = key.trim();
    if (!PROJ_RE.test(proj)) return showToast("Имя проекта: a-z, 0-9, точка, дефис (инстанс — через @)");
    if (!KEY_RE.test(k)) return showToast("Имя ключа как env-переменная: A-Z, 0-9, _");
    if (!value) return showToast("Пустое значение");
    if (value !== valueRepeat) return showToast("Значения не совпали");

    const { service, env } = splitProject(proj);
    const args = ["set", `${service}/${k}`, "--stdin"];
    if (note.trim()) args.push("--note", note.trim());
    if (kind) args.push("--kind", kind);
    if (env) args.push("-e", env);

    setBusy(true);
    try {
      // значение уходит в sec через stdin — не попадает в argv и историю
      const { stderr } = await runSecFull(args, value);
      rememberProject(proj);
      const hint = dupeHint(stderr);
      showToast(hint ? `${proj}/${k} сохранён. ${hint.text}` : `${proj}/${k} сохранён`, "success");
      refresh();
      close();
    } catch (err) {
      showToast(String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog title="Добавить секрет" onClose={close}>
      <div className="flex flex-col gap-3">
        <Field label="Проект">
          <ProjectInput value={project} onChange={setProject} projects={projects} />
        </Field>
        <Field label="Ключ">
          <Input autoFocus={!!initialProject} placeholder="API_TOKEN" className="font-mono" value={key} onChange={(e) => setKey(e.target.value)} />
        </Field>
        <Field label="Значение">
          <Input type="password" placeholder="секрет" value={value} onChange={(e) => setValue(e.target.value)} />
        </Field>
        <Field label="Повтори значение">
          <Input type="password" placeholder="ещё раз" value={valueRepeat} onChange={(e) => setValueRepeat(e.target.value)} />
        </Field>
        <div className="flex gap-3">
          <Field label="Тип" className="w-32">
            <Select className="w-full" value={kind} onChange={(e) => setKind(e.target.value)}>
              {KINDS.map((k) => (
                <option key={k || "none"} value={k}>
                  {k || "—"}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Заметка" className="flex-1">
            <Input placeholder="назначение ключа (без секрета)" value={note} onChange={(e) => setNote(e.target.value)} />
          </Field>
        </div>
        <div className="text-[11px] text-zinc-600">
          Значение уходит в sec через stdin — не попадает в argv и историю. Существующий ключ будет обновлён, старое значение — в истории (undo).
        </div>
        <div className="flex justify-end gap-2">
          <Button onClick={close}>Отмена</Button>
          <Button variant="primary" disabled={busy} onClick={submit}>
            Сохранить
          </Button>
        </div>
      </div>
    </Dialog>
  );
}

export function GenerateSecretDialog({ initialProject }: { initialProject?: string }) {
  const { data, openDialog, showToast, rememberProject, refresh } = useApp();
  const projects = Object.keys(data ?? {}).sort();
  const [project, setProject] = useState(initialProject ?? "");
  const [key, setKey] = useState("");
  const [length, setLength] = useState("32");
  const [symbols, setSymbols] = useState(false);
  const [copy, setCopy] = useState(true);
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const close = () => openDialog(null);

  const submit = async () => {
    const proj = project.trim();
    const k = key.trim();
    const len = parseInt(length, 10);
    if (!PROJ_RE.test(proj)) return showToast("Имя проекта: a-z, 0-9, точка, дефис (инстанс — через @)");
    if (!KEY_RE.test(k)) return showToast("Имя ключа как env-переменная: A-Z, 0-9, _");
    if (isNaN(len) || len < 8 || len > 1024) return showToast("Длина — от 8 до 1024");

    const { service, env } = splitProject(proj);
    const args = ["gen", `${service}/${k}`, "--len", String(len)];
    if (symbols) args.push("--symbols");
    if (copy) args.push("--clip");
    if (note.trim()) args.push("--note", note.trim());
    if (env) args.push("-e", env);

    setBusy(true);
    try {
      await runSec(args);
      rememberProject(proj);
      showToast(copy ? `${proj}/${k} сгенерирован и в буфере (не показан)` : `${proj}/${k} сгенерирован`, "success");
      refresh();
      close();
    } catch (err) {
      showToast(String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog title="Сгенерировать секрет" onClose={close}>
      <div className="flex flex-col gap-3">
        <Field label="Проект">
          <ProjectInput value={project} onChange={setProject} projects={projects} />
        </Field>
        <Field label="Ключ">
          <Input autoFocus={!!initialProject} placeholder="DB_PASSWORD" className="font-mono" value={key} onChange={(e) => setKey(e.target.value)} />
        </Field>
        <div className="flex items-end gap-3">
          <Field label="Длина" className="w-24">
            <Input value={length} onChange={(e) => setLength(e.target.value)} />
          </Field>
          <label className="flex items-center gap-1.5 pb-1.5 text-[12px] text-zinc-300">
            <input type="checkbox" checked={symbols} onChange={(e) => setSymbols(e.target.checked)} /> спецсимволы
          </label>
          <label className="flex items-center gap-1.5 pb-1.5 text-[12px] text-zinc-300">
            <input type="checkbox" checked={copy} onChange={(e) => setCopy(e.target.checked)} /> в буфер
          </label>
        </div>
        <Field label="Заметка">
          <Input placeholder="назначение ключа (без секрета)" value={note} onChange={(e) => setNote(e.target.value)} />
        </Field>
        <div className="text-[11px] text-zinc-600">Значение генерирует и сохраняет сам sec — оно нигде не показывается.</div>
        <div className="flex justify-end gap-2">
          <Button onClick={close}>Отмена</Button>
          <Button variant="primary" disabled={busy} onClick={submit}>
            Сгенерировать
          </Button>
        </div>
      </div>
    </Dialog>
  );
}

export function EditSecretDialog({ project, entry }: { project: string; entry: SecretEntry }) {
  const { openDialog, showToast, refresh } = useApp();
  const ref = `${project}/${entry.key}`;
  const currentNote = entry.meta?.note ?? "";
  const currentKind = entry.meta?.kind ?? "";
  const [value, setValue] = useState("");
  const [valueRepeat, setValueRepeat] = useState("");
  const [note, setNote] = useState(currentNote);
  const [kind, setKind] = useState(currentKind);
  const [busy, setBusy] = useState(false);
  const close = () => openDialog(null);

  const submit = async () => {
    const noteChanged = note.trim() !== currentNote;
    const kindChanged = kind !== currentKind;
    if (!value && !noteChanged && !kindChanged) return showToast("Нечего менять", "info");
    if (value && value !== valueRepeat) return showToast("Значения не совпали");

    setBusy(true);
    try {
      let hintText: string | undefined;
      if (value) {
        const { stderr } = await runSecFull(keyArgs("set", project, entry.key, "--stdin"), value);
        hintText = dupeHint(stderr)?.text;
      }
      if (noteChanged || kindChanged) {
        const flags: string[] = [];
        if (noteChanged) flags.push("--note", note.trim());
        if (kindChanged) flags.push("--kind", kind);
        await runSec(keyArgs("meta", project, entry.key, ...flags));
      }
      showToast(hintText ? `${ref} обновлён. ${hintText}` : `${ref} обновлён`, "success");
      refresh();
      close();
    } catch (err) {
      showToast(String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog title={`Редактировать ${ref}`} onClose={close}>
      <div className="flex flex-col gap-3">
        <div className="selectable font-mono text-[11px] text-zinc-500">
          {entry.enc === "b64" ? `файл, ${entry.chars} байт` : `${entry.chars} симв.`} · {entry.fingerprint}
        </div>
        <Field label="Новое значение">
          <Input type="password" placeholder="пусто — оставить текущее" value={value} onChange={(e) => setValue(e.target.value)} />
        </Field>
        <Field label="Повтори значение">
          <Input type="password" placeholder="ещё раз (если меняешь)" value={valueRepeat} onChange={(e) => setValueRepeat(e.target.value)} />
        </Field>
        <div className="flex gap-3">
          <Field label="Тип" className="w-32">
            <Select className="w-full" value={kind} onChange={(e) => setKind(e.target.value)}>
              {KINDS.map((k) => (
                <option key={k || "none"} value={k}>
                  {k || "—"}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Заметка" className="flex-1">
            <Input placeholder="пусто — снять заметку" value={note} onChange={(e) => setNote(e.target.value)} />
          </Field>
        </div>
        <div className="text-[11px] text-zinc-600">Новое значение уходит в sec через stdin; старое остаётся в истории (undo).</div>
        <div className="flex justify-end gap-2">
          <Button onClick={close}>Отмена</Button>
          <Button variant="primary" disabled={busy} onClick={submit}>
            Сохранить
          </Button>
        </div>
      </div>
    </Dialog>
  );
}
