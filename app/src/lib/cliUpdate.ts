// CLI sec ставится отдельным каском и обновляется независимо от приложения:
// новое приложение со старым CLI упрётся в незнакомые флаги.
import { invoke } from "@tauri-apps/api/core";
import { parseSecJSON, runSec } from "./sec";
import { cmpVersion } from "./semver";
import { GITHUB_REPO } from "./whatsNew";

/** Самая старая версия CLI, флаги которой покрывают вызовы приложения (паки share --all/--only). */
export const MIN_CLI = "0.9.0";

export interface CliStatus {
  version: string | null;
  commit: string | null;
  date: string | null;
  /** Почему версию узнать не удалось (нет бинаря и т.п.). */
  error: string | null;
  latest: string | null;
  /** Стоит каском — brew upgrade его обновит. */
  upgradable: boolean;
  path: string;
}

type Installed = Pick<CliStatus, "version" | "commit" | "date" | "error">;

async function installed(): Promise<Installed> {
  try {
    const data = parseSecJSON<{ version?: string; commit?: string; date?: string }>(
      await runSec(["version", "--json"]),
      {},
    );
    return { version: data.version ?? null, commit: data.commit ?? null, date: data.date ?? null, error: null };
  } catch (err) {
    return { version: null, commit: null, date: null, error: String(err) };
  }
}

/** Последний релиз CLI. В монорепо две линейки тегов: v* — CLI, app-v* — приложение. */
async function latestVersion(): Promise<string | null> {
  try {
    const res = await fetch(`https://api.github.com/repos/${GITHUB_REPO}/releases?per_page=30`, {
      headers: { Accept: "application/vnd.github+json" },
    });
    if (!res.ok) return null;
    const releases: { tag_name: string; draft?: boolean; prerelease?: boolean }[] = await res.json();
    const versions = releases
      .filter((r) => !r.draft && !r.prerelease && /^v\d/.test(r.tag_name))
      .map((r) => r.tag_name.slice(1))
      .sort((a, b) => cmpVersion(b, a));
    return versions[0] ?? null;
  } catch {
    return null;
  }
}

export async function cliStatus(withLatest: boolean): Promise<CliStatus> {
  const [cur, latest, install] = await Promise.all([
    installed(),
    withLatest ? latestVersion() : Promise.resolve(null),
    invoke<{ path: string; upgradable: boolean }>("cli_install").catch(() => ({ path: "", upgradable: false })),
  ]);
  return { ...cur, latest, ...install };
}

export function isBelowMin(s: CliStatus): boolean {
  return !!s.version && cmpVersion(s.version, MIN_CLI) < 0;
}

export function isOutdated(s: CliStatus): boolean {
  return isBelowMin(s) || (!!s.version && !!s.latest && cmpVersion(s.version, s.latest) < 0);
}

export function upgradeCli(): Promise<void> {
  return invoke<void>("upgrade_cli");
}
