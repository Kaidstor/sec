import { Action, ActionPanel, Form, Icon, LaunchProps, Toast, popToRoot, showToast } from "@raycast/api";
import { useCachedPromise } from "@raycast/utils";
import { useState } from "react";
import { ProjectField, rememberProject, useProjectPicker } from "./project-field";
import { KEY_RE, KINDS, listSecrets, runSecWithInput, splitProject } from "./sec";

interface FormValues {
  project: string;
  secretKey: string;
  value: string;
  valueRepeat: string;
  note: string;
  kind: string;
}

type Props = LaunchProps<{
  arguments: { project?: string; secretKey?: string };
  launchContext: { project?: string };
}>;

export default function AddSecret(props: Props) {
  const initialProject = props.launchContext?.project?.trim() || props.arguments?.project?.trim() || undefined;
  const initialKey = props.arguments?.secretKey?.trim();

  const { data, isLoading } = useCachedPromise(listSecrets, [], {
    failureToastOptions: { title: "sec ls не выполнился" },
  });
  const projects = Object.keys(data ?? {}).sort();

  const picker = useProjectPicker(projects, { isLoading, initial: initialProject });
  const [keyError, setKeyError] = useState<string>();
  const [repeatError, setRepeatError] = useState<string>();

  const submit = async (values: FormValues) => {
    const project = picker.submitProject(values.project);
    if (!project) return;
    const key = values.secretKey.trim();

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
      await rememberProject(project);
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
      <ProjectField picker={picker} />
      <Form.TextField
        id="secretKey"
        title="Ключ"
        placeholder="API_TOKEN"
        defaultValue={initialKey}
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
