import { Action, ActionPanel, Form, Icon, Toast, showToast, useNavigation } from "@raycast/api";
import { useState } from "react";
import { KINDS, SecretEntry, keyArgs, runSec, runSecWithInput } from "./sec";

interface FormValues {
  value: string;
  valueRepeat: string;
  note: string;
  kind: string;
}

// Редактирование существующего ключа: новое значение (пустое — не менять)
// и/или метаданные. Значение — через stdin, метаданные — через sec meta
// (пустой флаг очищает поле, см. cmd_meta.go).
export function EditSecretForm(props: { project: string; entry: SecretEntry; onChange: () => void }) {
  const { project, entry, onChange } = props;
  const ref = `${project}/${entry.key}`;
  const { pop } = useNavigation();
  const [repeatError, setRepeatError] = useState<string>();

  const currentNote = entry.meta?.note ?? "";
  const currentKind = entry.meta?.kind ?? "";

  const submit = async (values: FormValues) => {
    const value = values.value;
    const note = values.note.trim();
    const noteChanged = note !== currentNote;
    const kindChanged = values.kind !== currentKind;

    if (!value && !noteChanged && !kindChanged) {
      await showToast({ style: Toast.Style.Failure, title: "Нечего менять" });
      return;
    }
    if (value && value !== values.valueRepeat) {
      setRepeatError("Значения не совпали");
      return;
    }

    try {
      if (value) {
        await runSecWithInput(keyArgs("set", project, entry.key, "--stdin"), value);
      }
      if (noteChanged || kindChanged) {
        const flags: string[] = [];
        if (noteChanged) flags.push("--note", note);
        if (kindChanged) flags.push("--kind", values.kind);
        await runSec(keyArgs("meta", project, entry.key, ...flags));
      }
      await showToast({
        style: Toast.Style.Success,
        title: `${ref} обновлён`,
        message: value ? "старое значение — в истории (sec undo)" : "метаданные",
      });
      onChange();
      pop();
    } catch (err) {
      await showToast({ style: Toast.Style.Failure, title: "Не сохранилось", message: String(err) });
    }
  };

  return (
    <Form
      navigationTitle={`Редактировать ${ref}`}
      actions={
        <ActionPanel>
          <Action.SubmitForm title="Сохранить изменения" icon={Icon.Pencil} onSubmit={submit} />
        </ActionPanel>
      }
    >
      <Form.Description
        text={`${ref} — ${entry.enc === "b64" ? `файл, ${entry.chars} байт` : `${entry.chars} симв.`}, отпечаток ${entry.fingerprint}`}
      />
      <Form.PasswordField id="value" title="Новое значение" placeholder="пусто — оставить текущее" />
      <Form.PasswordField
        id="valueRepeat"
        title="Повтори значение"
        placeholder="ещё раз (если меняешь)"
        error={repeatError}
        onChange={() => setRepeatError(undefined)}
      />
      <Form.Separator />
      <Form.Dropdown id="kind" title="Тип" defaultValue={currentKind}>
        {KINDS.map((k) => (
          <Form.Dropdown.Item key={k || "none"} value={k} title={k || "—"} />
        ))}
      </Form.Dropdown>
      <Form.TextField
        id="note"
        title="Заметка"
        defaultValue={currentNote}
        placeholder="назначение ключа (пусто — снять заметку)"
      />
      <Form.Description text="Новое значение уходит в sec через stdin; старое остаётся в истории (sec undo)." />
    </Form>
  );
}
