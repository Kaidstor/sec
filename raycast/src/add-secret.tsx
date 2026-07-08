import { Action, ActionPanel, Form, Icon, Toast, popToRoot, showToast } from "@raycast/api";
import { useCachedPromise } from "@raycast/utils";
import { useState } from "react";
import { KEY_RE, PROJ_RE, listSecrets, runSecWithInput, splitProject } from "./sec";

const NEW_PROJECT = "__new__";
const KINDS = ["", "password", "apikey", "totp", "env"];

interface FormValues {
  project: string;
  newProject: string;
  secretKey: string;
  value: string;
  valueRepeat: string;
  note: string;
  kind: string;
}

export default function AddSecret() {
  const { data, isLoading } = useCachedPromise(listSecrets, [], {
    failureToastOptions: { title: "sec ls не выполнился" },
  });
  const projects = Object.keys(data ?? {}).sort();

  const [projectChoice, setProjectChoice] = useState<string>(NEW_PROJECT);
  const [keyError, setKeyError] = useState<string>();
  const [projError, setProjError] = useState<string>();
  const [repeatError, setRepeatError] = useState<string>();

  const submit = async (values: FormValues) => {
    const project = values.project === NEW_PROJECT ? values.newProject.trim() : values.project;
    const key = values.secretKey.trim();

    if (!PROJ_RE.test(project)) {
      setProjError("a-z, 0-9, точка, дефис, подчёркивание; инстанс через @env");
      return;
    }
    if (!KEY_RE.test(key)) {
      setKeyError("Имя как env-переменная: A-Z, 0-9, _");
      return;
    }
    if (!values.value) {
      await showToast({ style: Toast.Style.Failure, title: "Пустое значение" });
      return;
    }
    if (values.value !== values.valueRepeat) {
      setRepeatError("Значения не совпали");
      return;
    }

    const { service, env } = splitProject(project);
    const args = ["set", `${service}/${key}`, "--stdin"];
    if (values.note.trim()) args.push("--note", values.note.trim());
    if (values.kind) args.push("--kind", values.kind);
    if (env) args.push("-e", env);

    try {
      await runSecWithInput(args, values.value);
      await showToast({ style: Toast.Style.Success, title: `${project}/${key} сохранён` });
      await popToRoot();
    } catch (err) {
      await showToast({ style: Toast.Style.Failure, title: "Не сохранилось", message: String(err) });
    }
  };

  return (
    <Form
      isLoading={isLoading}
      actions={
        <ActionPanel>
          <Action.SubmitForm title="Сохранить секрет" icon={Icon.Lock} onSubmit={submit} />
        </ActionPanel>
      }
    >
      <Form.Dropdown id="project" title="Проект" value={projectChoice} onChange={setProjectChoice}>
        <Form.Dropdown.Item value={NEW_PROJECT} title="Новый проект…" icon={Icon.Plus} />
        {projects.map((p) => (
          <Form.Dropdown.Item key={p} value={p} title={p} icon={Icon.Folder} />
        ))}
      </Form.Dropdown>
      {projectChoice === NEW_PROJECT && (
        <Form.TextField
          id="newProject"
          title="Имя проекта"
          placeholder="whois или some-bot@commercial"
          error={projError}
          onChange={() => setProjError(undefined)}
        />
      )}
      <Form.TextField
        id="secretKey"
        title="Ключ"
        placeholder="API_TOKEN"
        error={keyError}
        onChange={() => setKeyError(undefined)}
      />
      <Form.PasswordField id="value" title="Значение" placeholder="секрет" />
      <Form.PasswordField
        id="valueRepeat"
        title="Повтори значение"
        placeholder="ещё раз"
        error={repeatError}
        onChange={() => setRepeatError(undefined)}
      />
      <Form.Separator />
      <Form.Dropdown id="kind" title="Тип" defaultValue="">
        {KINDS.map((k) => (
          <Form.Dropdown.Item key={k || "none"} value={k} title={k || "—"} />
        ))}
      </Form.Dropdown>
      <Form.TextField id="note" title="Заметка" placeholder="назначение ключа (метаданные, без секрета)" />
      <Form.Description text="Значение уходит в sec через stdin — не попадает в argv и историю. Существующий ключ будет обновлён, старое значение — в истории (sec undo)." />
    </Form>
  );
}
