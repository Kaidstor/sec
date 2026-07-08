import { Action, ActionPanel, Form, Icon, Toast, popToRoot, showHUD, showToast } from "@raycast/api";
import { useCachedPromise } from "@raycast/utils";
import { useState } from "react";
import { KEY_RE, PROJ_RE, listSecrets, runSec, splitProject } from "./sec";

const NEW_PROJECT = "__new__";

interface FormValues {
  project: string;
  newProject: string;
  secretKey: string;
  length: string;
  symbols: boolean;
  copy: boolean;
  note: string;
}

export default function GenerateSecret() {
  const { data, isLoading } = useCachedPromise(listSecrets, [], {
    failureToastOptions: { title: "sec ls не выполнился" },
  });
  const projects = Object.keys(data ?? {}).sort();

  const [projectChoice, setProjectChoice] = useState<string>(NEW_PROJECT);
  const [keyError, setKeyError] = useState<string>();
  const [projError, setProjError] = useState<string>();
  const [lenError, setLenError] = useState<string>();

  const submit = async (values: FormValues) => {
    const project = values.project === NEW_PROJECT ? values.newProject.trim() : values.project;
    const key = values.secretKey.trim();
    const len = parseInt(values.length, 10);

    if (!PROJ_RE.test(project)) {
      setProjError("a-z, 0-9, точка, дефис, подчёркивание; инстанс через @env");
      return;
    }
    if (!KEY_RE.test(key)) {
      setKeyError("Имя как env-переменная: A-Z, 0-9, _");
      return;
    }
    if (isNaN(len) || len < 8 || len > 1024) {
      setLenError("От 8 до 1024");
      return;
    }

    const { service, env } = splitProject(project);
    const args = ["gen", `${service}/${key}`, "--len", String(len)];
    if (values.symbols) args.push("--symbols");
    if (values.copy) args.push("--clip");
    if (values.note.trim()) args.push("--note", values.note.trim());
    if (env) args.push("-e", env);

    try {
      await runSec(args);
      if (values.copy) {
        await showHUD(`✓ ${project}/${key} сгенерирован и в буфере (не показан)`);
      } else {
        await showToast({ style: Toast.Style.Success, title: `${project}/${key} сгенерирован` });
        await popToRoot();
      }
    } catch (err) {
      await showToast({ style: Toast.Style.Failure, title: "Не сгенерировалось", message: String(err) });
    }
  };

  return (
    <Form
      isLoading={isLoading}
      actions={
        <ActionPanel>
          <Action.SubmitForm title="Сгенерировать и сохранить" icon={Icon.Bolt} onSubmit={submit} />
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
        placeholder="DB_PASSWORD"
        error={keyError}
        onChange={() => setKeyError(undefined)}
      />
      <Form.TextField
        id="length"
        title="Длина"
        defaultValue="32"
        error={lenError}
        onChange={() => setLenError(undefined)}
      />
      <Form.Checkbox id="symbols" label="Добавить спецсимволы" defaultValue={false} />
      <Form.Checkbox id="copy" label="Скопировать в буфер после генерации" defaultValue={true} />
      <Form.TextField id="note" title="Заметка" placeholder="назначение ключа (метаданные, без секрета)" />
      <Form.Description text="Значение генерирует и сохраняет сам sec — оно нигде не показывается." />
    </Form>
  );
}
