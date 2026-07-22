import {
  Action,
  ActionPanel,
  Alert,
  Color,
  Icon,
  Keyboard,
  LaunchType,
  List,
  Toast,
  confirmAlert,
  launchCommand,
  showHUD,
  showToast,
} from "@raycast/api";
import { useCachedPromise } from "@raycast/utils";
import { EditSecretForm } from "./edit-secret";
import { HistoryVersion, SecretEntry, keyArgs, keyHistory, listSecrets, runSec } from "./sec";

const KIND_COLOR: Record<string, Color> = {
  password: Color.Orange,
  apikey: Color.Blue,
  totp: Color.Green,
  env: Color.Purple,
};

export default function SearchSecrets() {
  const { data, isLoading, revalidate } = useCachedPromise(listSecrets, [], {
    keepPreviousData: true,
    failureToastOptions: { title: "sec ls не выполнился" },
  });

  const projects = Object.keys(data ?? {}).sort();

  return (
    <List isLoading={isLoading} searchBarPlaceholder="Проект или ключ…">
      <List.EmptyView
        icon={Icon.Lock}
        title="Секретов нет"
        description="Добавь через Add Secret или `sec set` в терминале"
      />
      {projects.map((project) => (
        <List.Section key={project} title={project} subtitle={String(data?.[project]?.length ?? 0)}>
          {(data?.[project] ?? []).map((entry) => (
            <SecretItem key={entry.key} project={project} entry={entry} onChange={revalidate} />
          ))}
        </List.Section>
      ))}
    </List>
  );
}

function SecretItem(props: { project: string; entry: SecretEntry; onChange: () => void }) {
  const { project, entry, onChange } = props;
  const ref = `${project}/${entry.key}`;
  const kind = entry.meta?.kind;
  const isTotp = kind === "totp";

  const accessories: List.Item.Accessory[] = [];
  if (kind) accessories.push({ tag: { value: kind, color: KIND_COLOR[kind] ?? Color.SecondaryText } });
  if (entry.history > 0) accessories.push({ icon: Icon.Clock, text: String(entry.history), tooltip: "версий в истории" });
  accessories.push({ text: `${entry.chars} симв.` });
  accessories.push({ date: new Date(entry.updatedAt), tooltip: `обновлён ${entry.updatedAt}` });

  const copyValue = async (extra: string[] = []) => {
    try {
      await runSec(keyArgs("get", project, entry.key, "--clip", ...extra));
      await showHUD(`✓ ${ref} — в буфере (значение не показано)`);
    } catch (err) {
      await showToast({ style: Toast.Style.Failure, title: "Не скопировалось", message: String(err) });
    }
  };

  const copyOtp = async () => {
    try {
      await runSec(keyArgs("otp", project, entry.key, "--clip"));
      await showHUD(`✓ TOTP ${ref} — в буфере`);
    } catch (err) {
      await showToast({ style: Toast.Style.Failure, title: "TOTP не получился", message: String(err) });
    }
  };

  const peek = async () => {
    try {
      const out = await runSec(keyArgs("get", project, entry.key, "--peek"));
      await showToast({ style: Toast.Style.Success, title: ref, message: out.trim() });
    } catch (err) {
      await showToast({ style: Toast.Style.Failure, title: "Peek не выполнился", message: String(err) });
    }
  };

  const remove = async () => {
    const ok = await confirmAlert({
      title: `Удалить ${ref}?`,
      message: "Ключ будет удалён из хранилища sec.",
      icon: Icon.Trash,
      primaryAction: { title: "Удалить", style: Alert.ActionStyle.Destructive },
    });
    if (!ok) return;
    try {
      await runSec(keyArgs("rm", project, entry.key));
      await showToast({ style: Toast.Style.Success, title: `${ref} удалён` });
      onChange();
    } catch (err) {
      await showToast({ style: Toast.Style.Failure, title: "Не удалилось", message: String(err) });
    }
  };

  return (
    <List.Item
      title={entry.key}
      subtitle={entry.meta?.note}
      keywords={[project, ...project.split(/[@._-]/), ...(entry.meta?.note?.split(/\s+/) ?? [])]}
      icon={isTotp ? Icon.Clock : Icon.Key}
      accessories={accessories}
      actions={
        <ActionPanel>
          <ActionPanel.Section>
            {isTotp ? (
              <>
                <Action title="Скопировать TOTP-код" icon={Icon.Clipboard} onAction={copyOtp} />
                <Action title="Скопировать Seed" icon={Icon.CopyClipboard} onAction={() => copyValue()} />
              </>
            ) : (
              <>
                <Action title="Скопировать значение" icon={Icon.Clipboard} onAction={() => copyValue()} />
                <Action
                  title="Скопировать (очистка через 60с)"
                  icon={Icon.Stopwatch}
                  shortcut={{ modifiers: ["opt", "cmd"], key: "c" }}
                  onAction={() => copyValue(["--clear-after", "60s"])}
                />
              </>
            )}
            <Action
              title="Показать маску (Peek)"
              icon={Icon.Eye}
              shortcut={{ modifiers: ["cmd"], key: "p" }}
              onAction={peek}
            />
          </ActionPanel.Section>
          <ActionPanel.Section>
            <Action.Push
              title="Редактировать секрет"
              icon={Icon.Pencil}
              shortcut={Keyboard.Shortcut.Common.Edit}
              target={<EditSecretForm project={project} entry={entry} onChange={onChange} />}
            />
            <Action.CopyToClipboard
              title="Скопировать ссылку proj/KEY"
              content={ref}
              shortcut={{ modifiers: ["cmd", "shift"], key: "c" }}
            />
            <Action.CopyToClipboard
              title="Скопировать отпечаток"
              content={entry.fingerprint}
              shortcut={{ modifiers: ["cmd", "shift"], key: "f" }}
            />
            <Action.Push
              title="История версий"
              icon={Icon.List}
              shortcut={{ modifiers: ["cmd"], key: "h" }}
              target={<HistoryView project={project} entry={entry} onChange={onChange} />}
            />
          </ActionPanel.Section>
          <ActionPanel.Section>
            <Action
              title={`Добавить секрет в «${project}»`}
              icon={Icon.Plus}
              shortcut={Keyboard.Shortcut.Common.New}
              onAction={() => launchCommand({ name: "add-secret", type: LaunchType.UserInitiated, context: { project } })}
            />
            <Action
              title={`Сгенерировать секрет в «${project}»`}
              icon={Icon.Bolt}
              shortcut={{ modifiers: ["cmd", "shift"], key: "g" }}
              onAction={() => launchCommand({ name: "generate-secret", type: LaunchType.UserInitiated, context: { project } })}
            />
            <Action
              title="Обновить список"
              icon={Icon.ArrowClockwise}
              shortcut={Keyboard.Shortcut.Common.Refresh}
              onAction={onChange}
            />
            <Action
              title="Удалить ключ"
              icon={Icon.Trash}
              style={Action.Style.Destructive}
              shortcut={Keyboard.Shortcut.Common.Remove}
              onAction={remove}
            />
          </ActionPanel.Section>
        </ActionPanel>
      }
    />
  );
}

function HistoryView(props: { project: string; entry: SecretEntry; onChange: () => void }) {
  const { project, entry, onChange } = props;
  const ref = `${project}/${entry.key}`;
  const { data, isLoading, revalidate } = useCachedPromise(
    (p: string, k: string) => keyHistory(p, k),
    [project, entry.key],
    { failureToastOptions: { title: "sec history не выполнился" } },
  );

  const posTitle = (v: HistoryVersion) =>
    v.pos === 0 ? "текущее" : v.pos > 0 ? `+${v.pos} (отменено, redo вернёт)` : String(v.pos);

  const step = async (cmd: "undo" | "redo") => {
    try {
      await runSec(keyArgs(cmd, project, entry.key));
      await showToast({ style: Toast.Style.Success, title: `${cmd} — готово`, message: ref });
      revalidate();
      onChange();
    } catch (err) {
      await showToast({ style: Toast.Style.Failure, title: `${cmd} не выполнился`, message: String(err) });
    }
  };

  return (
    <List isLoading={isLoading} navigationTitle={`История ${ref}`}>
      {(data ?? []).map((v) => (
        <List.Item
          key={v.pos}
          title={posTitle(v)}
          icon={v.pos === 0 ? Icon.CheckCircle : v.pos > 0 ? Icon.ArrowUp : Icon.ArrowDown}
          accessories={[
            { text: v.fingerprint },
            { text: `${v.chars} симв.` },
            { date: new Date(v.updatedAt) },
          ]}
          actions={
            <ActionPanel>
              <Action title="Undo (шаг назад)" icon={Icon.Undo} onAction={() => step("undo")} />
              <Action title="Redo (шаг вперёд)" icon={Icon.Redo} onAction={() => step("redo")} />
              <Action.CopyToClipboard title="Скопировать отпечаток" content={v.fingerprint} />
            </ActionPanel>
          }
        />
      ))}
    </List>
  );
}
