import { Form, Icon, LocalStorage } from "@raycast/api";
import { usePromise } from "@raycast/utils";
import { useState } from "react";
import { PROJ_RE } from "./sec";

// Пункт «Создать проект» в дропдауне; реальное имя живёт в candidate (текст поиска).
export const CREATE_VALUE = "__create__";

const LAST_PROJECT_KEY = "last-project";

// Запомнить проект как последний использованный — формы предвыберут его в следующий раз.
export function rememberProject(project: string): Promise<void> {
  return LocalStorage.setItem(LAST_PROJECT_KEY, project);
}

function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  const row = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let diag = row[0];
    row[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const tmp = row[j];
      row[j] = Math.min(row[j] + 1, row[j - 1] + 1, diag + (a[i - 1] === b[j - 1] ? 0 : 1));
      diag = tmp;
    }
  }
  return row[b.length];
}

// Проекты, отличающиеся от name только регистром или на 1–2 символа, —
// авто-создание тихо плодит дубли из опечаток, предупреждаем заранее.
export function similarProjects(name: string, projects: string[]): string[] {
  const lower = name.toLowerCase();
  return projects.filter((p) => {
    if (p === name) return false;
    const pl = p.toLowerCase();
    const limit = Math.min(pl.length, lower.length) >= 5 ? 2 : 1;
    return levenshtein(pl, lower) <= limit;
  });
}

export interface ProjectPicker {
  projects: string[];
  isLoading: boolean;
  value: string;
  candidate: string;
  error?: string;
  onChange: (value: string) => void;
  onSearchTextChange: (text: string) => void;
  /** Валидирует values.project из формы; при ошибке ставит error на поле и возвращает undefined. */
  submitProject: (formValue: string) => string | undefined;
}

export function useProjectPicker(projects: string[], opts: { isLoading?: boolean; initial?: string } = {}): ProjectPicker {
  const { initial } = opts;
  const [selected, setSelected] = useState<string>();
  // Последний непустой ввод в поиске дропдауна; не сбрасывается при закрытии,
  // чтобы выбранный пункт «Создать …» не исчезал вместе с текстом поиска.
  const [typed, setTyped] = useState("");
  const [error, setError] = useState<string>();
  const { data: lastUsed } = usePromise(async () => (await LocalStorage.getItem<string>(LAST_PROJECT_KEY)) ?? null);

  const initialUnknown = initial !== undefined && !projects.includes(initial);
  const candidate = typed || (initialUnknown ? initial : "");

  const fallback = initial
    ? initialUnknown
      ? CREATE_VALUE
      : initial
    : lastUsed && projects.includes(lastUsed)
      ? lastUsed
      : (projects[0] ?? CREATE_VALUE);
  const value = selected ?? fallback;

  const resolve = (formValue: string) => (formValue === CREATE_VALUE ? candidate.trim() : formValue);

  return {
    projects,
    isLoading: opts.isLoading ?? false,
    value,
    candidate,
    error,
    onChange: (v) => {
      // Raycast зовёт onChange и при программной установке value — фиксируем
      // выбор только на реальную смену, иначе дефолт «залипнет» раньше времени.
      if (v !== value) setSelected(v);
      setError(undefined);
    },
    onSearchTextChange: (text) => {
      const t = text.trim();
      if (t) setTyped(t);
      setError(undefined);
    },
    submitProject: (formValue) => {
      const name = resolve(formValue);
      if (!name) {
        setError("Набери имя нового проекта в поиске дропдауна или выбери существующий");
        return undefined;
      }
      if (!PROJ_RE.test(name)) {
        setError("a-z, 0-9, точка, дефис, подчёркивание; инстанс через @env");
        return undefined;
      }
      return name;
    },
  };
}

// Дропдаун-«комбобокс»: поиск по существующим проектам + пункт «Создать …» для
// нового имени (sec set создаёт проект неявно). Под полем — предупреждение,
// если новое имя подозрительно похоже на существующее.
export function ProjectField(props: { picker: ProjectPicker }) {
  const p = props.picker;
  const showCreate = p.projects.length === 0 || (p.candidate !== "" && !p.projects.includes(p.candidate));
  const similar = p.value === CREATE_VALUE && p.candidate ? similarProjects(p.candidate, p.projects) : [];

  return (
    <>
      <Form.Dropdown
        id="project"
        title="Проект"
        value={p.value}
        error={p.error}
        isLoading={p.isLoading}
        filtering
        onChange={p.onChange}
        onSearchTextChange={p.onSearchTextChange}
        info="Новый проект: набери имя в поиске дропдауна и выбери «Создать …» — sec заведёт его при сохранении."
      >
        {showCreate && (
          <Form.Dropdown.Item
            value={CREATE_VALUE}
            title={p.candidate ? `Создать «${p.candidate}»` : "Новый проект — набери имя в поиске"}
            icon={Icon.Plus}
          />
        )}
        {p.projects.map((x) => (
          <Form.Dropdown.Item key={x} value={x} title={x} icon={Icon.Folder} />
        ))}
      </Form.Dropdown>
      {similar.length > 0 && (
        <Form.Description
          title="Не опечатка?"
          text={`«${p.candidate}» похож на ${similar.map((s) => `«${s}»`).join(", ")} — новый проект будет создан отдельно.`}
        />
      )}
    </>
  );
}
