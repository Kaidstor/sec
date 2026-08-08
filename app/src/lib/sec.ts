import { invoke } from "@tauri-apps/api/core";

export interface SecOutput {
  stdout: string;
  stderr: string;
}

// Значения секретов через эти вызовы не проходят: копирование делает сам CLI
// (--clip), просмотр — маской (--peek). Исключение — add/edit-формы, где
// значение вводит пользователь.
export async function runSecFull(args: string[], stdin?: string): Promise<SecOutput> {
  return invoke<SecOutput>("run_sec", { args, stdin: stdin ?? null });
}

export async function runSec(args: string[], stdin?: string): Promise<string> {
  return (await runSecFull(args, stdin)).stdout;
}

// --- типы вывода sec ---

export interface SecretMeta {
  note?: string;
  kind?: string;
  [key: string]: unknown;
}

export interface SecretEntry {
  key: string;
  ref?: string; // CLI-адрес родителя, если ключ — ссылка
  enc?: string; // "b64" — бинарный (файловый) секрет: в буфер/env не отдаётся, chars — размер в байтах
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

export interface ShareLink {
  id: string;
  createdAt: string;
  expiresAt: string;
  once: boolean;
  claims: number;
}

export function isBinaryEntry(entry: SecretEntry): boolean {
  return entry.enc === "b64";
}

// Команда для терминала: единственный способ достать бинарный секрет — в файл.
export function getOutCommand(project: string, key: string): string {
  return `sec get ${project}/${key} --out <файл>`;
}

// --- адресация: внутренний проект "service@profile" совпадает с CLI-формой,
// в argv он уходит как есть; splitProject остаётся для отображения (бейдж
// профиля в списке) ---

export interface ProjectRef {
  service: string;
  profile?: string;
}

export function splitProject(project: string): ProjectRef {
  const at = project.indexOf("@");
  if (at === -1) return { service: project };
  return { service: project.slice(0, at), profile: project.slice(at + 1) };
}

// Собирает argv команды над одним ключом: project[@profile]/KEY.
export function keyArgs(cmd: string, project: string, key: string, ...extra: string[]): string[] {
  return [cmd, `${project}/${key}`, ...extra];
}

export async function listSecrets(): Promise<SecretStore> {
  const out = await runSec(["ls", "--json"]);
  return JSON.parse(out || "{}") as SecretStore;
}

export async function keyHistory(project: string, key: string): Promise<HistoryVersion[]> {
  const out = await runSec(keyArgs("history", project, key, "--json"));
  return JSON.parse(out || "[]") as HistoryVersion[];
}

export async function shareLinks(): Promise<ShareLink[]> {
  const out = await runSec(["share", "ls", "--json"]);
  return JSON.parse(out || "[]") as ShareLink[];
}

export interface ShareResult {
  url: string;
  note: string; // пояснение CLI из stderr («сгорит …»)
}

// Ссылка на один ключ. URL не секрет по построению (это цель передачи),
// показывать его в UI можно.
export async function shareKey(
  project: string,
  key: string,
  ttl: string,
  multi: boolean,
): Promise<ShareResult> {
  const args = keyArgs("share", project, key, "--ttl", ttl, "--no-clip");
  if (multi) args.push("--multi");
  const out = await runSecFull(args);
  return { url: out.stdout.trim(), note: cleanStderr(out.stderr) };
}

// Пак: весь проект (--all) или выбранные ключи (--only).
export async function sharePack(
  project: string,
  keys: string[] | null,
  ttl: string,
  multi: boolean,
): Promise<ShareResult> {
  const args = ["share", project, "--ttl", ttl, "--no-clip"];
  if (keys && keys.length) args.push("--only", keys.join(","));
  else args.push("--all");
  if (multi) args.push("--multi");
  const out = await runSecFull(args);
  return { url: out.stdout.trim(), note: cleanStderr(out.stderr) };
}

export function cleanStderr(s: string): string {
  return s.replace(/^sec:\s*/gm, "").trim();
}

export interface DupeHint {
  text: string; // «значение X уже есть в Y — вместо копии можно ссылку: …»
}

// Подсказка sec о дубле значения из stderr после set (dupehint.go).
export function dupeHint(stderr: string): DupeHint | undefined {
  const line = cleanStderr(stderr)
    .split("\n")
    .find((l) => l.includes("уже есть в"));
  return line ? { text: line } : undefined;
}

// Валидация как в CLI (router.go), чтобы падать до вызова с понятной ошибкой.
export const KEY_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
export const PROJ_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*(@[A-Za-z0-9][A-Za-z0-9._-]*)?$/;

// Типы из sec set/gen/meta --kind (пустой — «без типа»).
export const KINDS = ["", "password", "apikey", "totp", "env", "config", "file"];

export const TTL_OPTIONS = ["1h", "6h", "24h", "3d", "7d"];
