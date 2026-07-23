// sec — локальные секреты для проектов, сделан под безопасную работу с
// агентами: значения не появляются в argv/истории/чате. Хранилище — один файл
// XChaCha20-Poly1305, мастер-ключ — в системном хранилище ОС: macOS Keychain /
// Linux libsecret / Windows Credential Manager (fallback: env / файл).
//
// Точка входа тонкая: вся логика — в пакетах internal/. Карта:
//
//	internal/command   CLI-слой: роутер Run, usage, разбор <proj>/<KEY>, все команды
//	internal/store     хранилище: модель, XChaCha20-Poly1305, персист, история,
//	                   ссылки/наследование, merge, адресация, отпечатки
//	internal/keyring   мастер-ключ: env SEC_KEY → системное хранилище ОС → файл
//	internal/backup    переносной бэкап: Argon2id + XChaCha20 (Seal/Open)
//	internal/totp      RFC 6238 (алгоритм TOTP)
//	internal/dotenv    парсинг/форматирование .env
//	internal/audit     журнал обращений (JSONL, без значений)
//	internal/infisical заменяемый бэкенд Infisical (сейчас — их CLI)
package main

import (
	"os"

	"github.com/kaidstor/sec/internal/command"
)

func main() { os.Exit(command.Run(os.Args[1:])) }
