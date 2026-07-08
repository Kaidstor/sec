import { getPreferenceValues } from "@raycast/api";
import { execFile, spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

// Кандидаты на путь к бинарю: brew (arm/intel), затем go install.
const CANDIDATES = [
  "/opt/homebrew/bin/sec",
  "/usr/local/bin/sec",
  `${homedir()}/go/bin/sec`,
];

interface Preferences {
  secPath?: string;
}

export function secBinary(): string {
  const { secPath } = getPreferenceValues<Preferences>();
  if (secPath && secPath.trim()) return secPath.trim();
  const found = CANDIDATES.find((p) => existsSync(p));
  if (!found) {
    throw new Error(
      "Бинарь sec не найден. Установи: brew install kaidstor/tap/sec — или укажи путь в настройках расширения.",
    );
  }
  return found;
}

// die() в CLI пишет "sec: <текст>" в stderr — вытаскиваем текст без префикса.
function extractError(err: unknown): string {
  const e = err as { stderr?: string; message?: string };
  const stderr = (e.stderr ?? "").trim();
  if (stderr) return stderr.replace(/^sec:\s*/gm, "").trim();
  return e.message ?? String(err);
}

export async function runSec(args: string[]): Promise<string> {
  try {
    const { stdout } = await execFileAsync(secBinary(), args, {
      maxBuffer: 8 * 1024 * 1024,
    });
    return stdout;
  } catch (err) {
    throw new Error(extractError(err));
  }
}

// Для sec set --stdin: значение уходит через pipe, не через argv.
export function runSecWithInput(args: string[], input: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(secBinary(), args, { stdio: ["pipe", "pipe", "pipe"] });
    let out = "";
    let errOut = "";
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (errOut += d));
    child.on("error", (e) => reject(new Error(e.message)));
    child.on("close", (code) => {
      if (code === 0) resolve(out);
      else reject(new Error(errOut.replace(/^sec:\s*/gm, "").trim() || `sec завершился с кодом ${code}`));
    });
    child.stdin.write(input);
    child.stdin.end();
  });
}

// --- типы вывода sec ---

export interface SecretMeta {
  note?: string;
  kind?: string;
  [key: string]: unknown;
}

export interface SecretEntry {
  key: string;
  updatedAt: string;
  history: number;
  chars: number;
  fingerprint: string;
  meta?: SecretMeta;
}

export type SecretStore = Record<string, SecretEntry[]>;

export interface HistoryVersion {
  pos: number; // +N — отменённое (redo), 0 — текущее, -N — история
  fingerprint: string;
  chars: number;
  updatedAt: string;
}

// --- адресация: внутренний проект "service@env" → service + флаг -e ---

export interface ProjectRef {
  service: string;
  env?: string;
}

export function splitProject(project: string): ProjectRef {
  const at = project.indexOf("@");
  if (at === -1) return { service: project };
  return { service: project.slice(0, at), env: project.slice(at + 1) };
}

// Собирает argv команды над одним ключом: сервис/KEY + -e для инстанса.
export function keyArgs(cmd: string, project: string, key: string, ...extra: string[]): string[] {
  const { service, env } = splitProject(project);
  const args = [cmd, `${service}/${key}`, ...extra];
  if (env) args.push("-e", env);
  return args;
}

export async function listSecrets(): Promise<SecretStore> {
  const out = await runSec(["ls", "--json"]);
  return JSON.parse(out || "{}") as SecretStore;
}

export async function keyHistory(project: string, key: string): Promise<HistoryVersion[]> {
  const out = await runSec(keyArgs("history", project, key, "--json"));
  return JSON.parse(out || "[]") as HistoryVersion[];
}

// Валидация как в CLI (router.go), чтобы падать до вызова, с понятной ошибкой.
export const KEY_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
export const PROJ_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*(@[A-Za-z0-9][A-Za-z0-9._-]*)?$/;
