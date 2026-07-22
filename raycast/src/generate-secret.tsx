import { Action, ActionPanel, Form, Icon, LaunchProps, Toast, popToRoot, showHUD, showToast } from "@raycast/api";
import { useCachedPromise } from "@raycast/utils";
import { useState } from "react";
import { ProjectField, rememberProject, useProjectPicker } from "./project-field";
import { KEY_RE, listSecrets, runSec, splitProject } from "./sec";

interface FormValues {
  project: string;
  secretKey: string;
  length: string;
  symbols: boolean;
  copy: boolean;
  note: string;
}

type Props = LaunchProps<{
  arguments: { project?: string; secretKey?: string };
  launchContext: { project?: string };
}>;

export default function GenerateSecret(props: Props) {
  const initialProject = props.launchContext?.project?.trim() || props.arguments?.project?.trim() || undefined;
  const initialKey = props.arguments?.secretKey?.trim();

  const { data, isLoading } = useCachedPromise(listSecrets, [], {
    failureToastOptions: { title: "sec ls не выполнился" },
  });
  const projects = Object.keys(data ?? {}).sort();

  const picker = useProjectPicker(projects, { isLoading, initial: initialProject });
  const [keyError, setKeyError] = useState<string>();
  const [lenError, setLenError] = useState<string>();

  const submit = async (values: FormValues) => {
    const project = picker.submitProject(values.project);
    if (!project) return;
    const key = values.secretKey.trim();
    const len = parseInt(values.length, 10);

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
      await rememberProject(project);
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
      <ProjectField picker={picker} />
      <Form.TextField
        id="secretKey"
        title="Ключ"
        placeholder="DB_PASSWORD"
        defaultValue={initialKey}
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
