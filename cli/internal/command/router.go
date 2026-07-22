// Пакет command — CLI-слой sec: роутер (Run), usage, разбор <proj>/<KEY>,
// общие хелперы команд и сами обработчики команд (файлы cmd_*.go, а также
// backup/rekey/render/scan/sync/fingerprint/input). Доменную логику берёт из
// internal/{store,keyring,backup,totp,dotenv,audit,infisical}.
package command

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/kaidstor/sec/internal/store"
)

var (
	keyRe  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	projRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	envRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
)

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "sec: "+format+"\n", a...)
	os.Exit(2)
}

// cwdProject — проект по умолчанию: имя текущей директории.
func cwdProject() string {
	wd, err := os.Getwd()
	if err != nil {
		return ""
	}
	return strings.ToLower(filepathBase(wd))
}

func filepathBase(p string) string {
	p = strings.TrimRight(p, "/")
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

// Адресация проекта с инстансом/окружением — в store.ProjKey / store.BaseAndEnv.

func checkEnv(env string) {
	if env != "" && !envRe.MatchString(env) {
		die("некорректное имя окружения %q (a-z, 0-9, точка, дефис, подчёркивание)", env)
	}
}

// resolveRef разбирает "<service>/<KEY>" либо просто "<KEY>" (тогда сервис —
// имя текущей директории) и склеивает с инстансом env во внутренний ключ проекта.
func resolveRef(ref, env string) (string, string) {
	service, key, ok := strings.Cut(ref, "/")
	if !ok {
		service, key = cwdProject(), ref
	}
	if !projRe.MatchString(service) {
		die("некорректное имя проекта %q (a-z, 0-9, точка, дефис, подчёркивание)", service)
	}
	checkEnv(env)
	if !keyRe.MatchString(key) {
		die("некорректное имя ключа %q (должно годиться как env-переменная: A-Z, 0-9, _)", key)
	}
	return store.ProjKey(service, env), key
}

// resolveProj склеивает имя сервиса (из аргумента или cwd) с инстансом env —
// для команд, работающих над проектом целиком (run/export/import/push/ls/rm).
func resolveProj(service, env string) string {
	if service == "" {
		service = cwdProject()
	}
	if !projRe.MatchString(service) {
		die("некорректное имя проекта %q", service)
	}
	checkEnv(env)
	return store.ProjKey(service, env)
}

// resolveKeyRef — общий хвост команд над одним ключом (set/gen/get/history/
// undo/redo/forget/meta/otp/verify): берёт ref (первый позиционный или
// fs.Arg(0)), применяет инстанс (-e/.sec) и возвращает внутренний проект+ключ.
// При отсутствии ref печатает usage и выходит.
func resolveKeyRef(ref string, fs *flag.FlagSet, explicitEnv, usage string) (string, string) {
	if ref == "" {
		ref = fs.Arg(0)
	}
	if ref == "" {
		die("укажи ключ: %s", usage)
	}
	return resolveRef(ref, resolvedEnv(explicitEnv, refService(ref)))
}

// resolveServiceProj — общий хвост команд над проектом целиком (run/export/
// import/push): сервис из аргумента, иначе fs.Arg(0), иначе имя папки; плюс
// инстанс (-e/.sec). Возвращает внутренний проект и разрешённый инстанс.
func resolveServiceProj(service string, fs *flag.FlagSet, explicitEnv string) (string, string) {
	if service == "" {
		service = fs.Arg(0)
	}
	if service == "" {
		service = cwdProject()
	}
	env := resolvedEnv(explicitEnv, service)
	return resolveProj(service, env), env
}

// collectPositionals разбирает args, где позиционные аргументы и флаги
// (включая -e/--env) идут вперемешку: собирает ведущие позиционные, парсит
// остаток флагсетом и добавляет хвостовые. Нужно там, где позиционных
// несколько — стандартный flag останавливается на первом же (mv/cp/diff).
func collectPositionals(fs *flag.FlagSet, args []string) []string {
	var pos []string
	for len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		pos = append(pos, args[0])
		args = args[1:]
	}
	_ = fs.Parse(args)
	return append(pos, fs.Args()...)
}

// mustSecret достаёт секрет или выходит с «нет proj/key» — общий хвост команд
// над уже существующим ключом.
func mustSecret(st *store.Store, proj, key string) store.Secret {
	sec, ok := st.Projects[proj][key]
	if !ok {
		die("нет %s/%s", proj, key)
	}
	return sec
}

// selectKeys собирает KEY→VALUE проекта: все ключи или только перечисленные в
// only (через запятую). Отсутствие запрошенного ключа — фатально (run/push).
func selectKeys(keys map[string]store.Secret, only, projLabel string) map[string]string {
	out := map[string]string{}
	if only == "" {
		for k, s := range keys {
			out[k] = s.Value
		}
		return out
	}
	var missing []string
	for _, k := range strings.Split(only, ",") {
		k = strings.TrimSpace(k)
		if s, ok := keys[k]; ok {
			out[k] = s.Value
		} else {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		die("в проекте %s нет ключей: %s", projLabel, strings.Join(missing, ", "))
	}
	return out
}

// addEnvFlag регистрирует -e/--env на флагсете и возвращает резолвер значения
// (длинная форма приоритетнее, если заданы обе).
func addEnvFlag(fs *flag.FlagSet) func() string {
	short := fs.String("e", "", "инстанс/окружение (напр. commercial); умолч. — из .sec или без инстанса")
	long := fs.String("env", "", "то же, что -e (длинная форма)")
	return func() string {
		if *long != "" {
			return *long
		}
		return *short
	}
}

// splitArgs выделяет первый позиционный аргумент до флагов (как prod-db),
// чтобы работало и `cmd proj --flag`, и `cmd --flag proj`.
func splitArgs(args []string) (string, []string) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return args[0], args[1:]
	}
	return "", args
}

const usage = `sec — локальные секреты для проектов, безопасные для работы с агентами:
значения не попадают в argv/историю/чат. Хранилище — файл XChaCha20-Poly1305,
мастер-ключ — в macOS Keychain (fallback: env SEC_KEY / файл).

Использование:
  sec set <proj>/<KEY>                 сохранить (скрытый ввод, дважды)
  sec set <proj>/<KEY> --clipboard     взять значение из буфера обмена
  cat token.txt | sec set <proj>/<KEY> значение из stdin
  sec gen <proj>/<KEY> [--len 32]      сгенерировать и сохранить, не показывая
  sec get <proj>/<KEY> [--clip]        показать (или молча в буфер)
  sec get <proj>/<KEY> --peek          маска ab…yz + длина (безопасно для чата)
  sec get <proj>/<KEY> --fingerprint   отпечаток fp:… (безопасно для чата)
  sec get <proj>/<KEY> --prev 1        показать предыдущее значение
  sec get <proj>/<KEY> --once          показать и сразу удалить (одноразовая передача)
  sec verify <proj>/<KEY>              сверить переданное значение с сохранённым
  sec history <proj>/<KEY> [--json]    версии значения (маскированно, до 5, +redo)
  sec undo <proj>/<KEY>                шаг назад по истории (redo вернёт вперёд)
  sec redo <proj>/<KEY>                вернуть значение, отменённое undo
  sec forget <proj>/<KEY>              стереть историю и redo (после ротации)
  sec meta <proj>/<KEY> [--note ...]   несекретные метаданные (назначение, ротация)
  sec otp <proj>/<KEY> [--clip]        TOTP-код из сохранённого seed (RFC 6238)
  sec ls [proj] [-l|--json]            список проектов / ключей (без значений)
  sec ls [proj] --filter <шаблон>      только совпавшие имена (подстрока/glob)
  sec find <шаблон> [-l|--json]        найти ключи по всему хранилищу → proj/KEY
  sec diff <projA> <projB>             сравнить проекты по отпечаткам (без значений)
  sec mv <proj>/<KEY> <p2>[/<KEY2>]    перенести/переименовать (без раскрытия)
  sec cp <proj>/<KEY> <p2>[/<KEY2>]    скопировать ключ (оригинал на месте)
  sec link <proj>/<KEY> <род>/<KEY2>   живая ссылка на чужое значение (менять — в родителе)
  sec unlink <proj>/<KEY>              снять ссылку (значение станет собственным)
  sec extend <proj> --from <род>       видеть все ключи родительской пачки read-only
  sec rm <proj>/<KEY>                  удалить ключ
  sec rm <proj> --all                  удалить проект целиком
  sec run [proj] [--only A,B] -- cmd   запустить cmd с env из проекта
  sec export [proj] --file .env        записать .env (только в файл)
  sec import [proj] [path/to/.env]     импортировать ключи из .env (умолч. ./.env)
  sec import [proj] --from-infisical   импортировать из Infisical (их CLI)
  sec push [proj] --to-infisical       отправить ключи проекта в Infisical
  sec check [proj] [--file .sec]       проверить, что заведены ключи из манифеста
  sec scan <path...|-|--staged>        найти сохранённые значения в файлах/диффе
  sec redact <path...|->                вычистить сохранённые значения из текста → stdout
  sec render <tpl> --file <out>        шаблон с {{ secret "proj/KEY" }} → файл
  sec stale [proj] [--older-than 90d]  какие секреты пора ротировать
  sec doctor                           здоровье хранилища (права, дубли, ротация)
  sec backup --file <f>                весь стор одним файлом под passphrase
  sec restore --file <f> [--replace]   восстановить (умолч. merge, старое в истории)
  sec sync --file <blob>               синхронизация через общий passphrase-блоб
  sec rekey                            ротация мастер-ключа с перешифровкой стора
  sec log [proj[/KEY]] [-n 20] [--json] журнал обращений (кто/когда/что, без значений)
  sec info [--json]                    путь к хранилищу, бэкенд ключа, статистика
  sec completion zsh|bash|fish         скрипт автодополнения для шелла
  sec version                          версия CLI и платформа

Если <proj> не указан (просто KEY или совсем пусто) — берётся имя текущей папки.

Инстансы/окружения (-e/--env): у одного сервиса может быть несколько наборов
значений — например разные компании/стенды. Флаг -e работает почти во всех
командах над значениями (set/gen/get/run/export/import/push/ls/rm/mv/cp/meta/…):
  sec set some-bot/TOKEN -e commercial     # значение инстанса commercial
  sec run some-bot -e max -- just start    # запустить инстанс max
  sec ls some-bot                          # покажет инстансы
  sec diff some-bot -e commercial max      # сравнить два инстанса
Инстансы можно объявить в .sec (project/envs/default/keys); дефолт из .sec
подставляется, когда -e не указан. Сервисы без инстансов работают как раньше.
У import/push -e задаёт инстанс в sec, а окружение Infisical — отдельный
флаг --infisical-env.

Ссылки и наследование (общие значения между пачками/инстансами):
  sec link app/DB_URL shared/DATABASE_URL   app/DB_URL = живое значение родителя
  sec extend app --from base                app видит все ключи base read-only
Ссылка резолвится в текущее значение родителя при чтении (get/run/export/…),
поэтому источник правды один. Редактировать значение в потомке нельзя — sec
подскажет, где родитель; sec unlink делает значение собственным, sec set
--override даёт проекту свой ключ поверх унаследованного. Инстанс родителя —
--parent-env (умолч. как у потомка).

Флаги set:
  --clipboard   взять значение из буфера обмена (pbpaste)
  --clear       очистить буфер после сохранения (вместе с --clipboard)
  --stdin       читать из stdin (включается и само, если stdin — пайп)

Флаги gen: --len N (умолч. 32), --symbols (добавить спецсимволы), --clip

Переменные окружения:
  SEC_STORE       путь к хранилищу (умолч. ~/.local/share/sec/store.enc)
  SEC_KEY         мастер-ключ hex64 — в обход Keychain (для серверов/CI)
  SEC_KEY_FILE    путь к файлу мастер-ключа (умолч. ~/.config/sec/key)
  SEC_PASSPHRASE  passphrase для backup/restore без интерактива
`

// Run — точка входа CLI: разбирает args (без имени программы), маршрутизирует
// команду и возвращает код выхода. main() из пакета main делегирует сюда.
func Run(args []string) int {
	if len(args) == 0 {
		fmt.Print(usage)
		return 2
	}
	switch args[0] {
	case "-h", "--help", "help":
		fmt.Print(usage)
		return 0
	case "-v", "--version", "version":
		return versionCommand(args[1:])
	case "set":
		return setCommand(args[1:])
	case "gen", "generate":
		return genCommand(args[1:])
	case "get":
		return getCommand(args[1:])
	case "mv", "move":
		return mvCommand(args[1:])
	case "link":
		return linkCommand(args[1:])
	case "unlink":
		return unlinkCommand(args[1:])
	case "extend":
		return extendCommand(args[1:])
	case "render":
		return renderCommand(args[1:])
	case "backup":
		return backupCommand(args[1:])
	case "restore":
		return restoreCommand(args[1:])
	case "history":
		return historyCommand(args[1:])
	case "undo":
		return undoCommand(args[1:])
	case "redo":
		return redoCommand(args[1:])
	case "forget":
		return forgetCommand(args[1:])
	case "otp":
		return otpCommand(args[1:])
	case "meta":
		return metaCommand(args[1:])
	case "stale":
		return staleCommand(args[1:])
	case "doctor":
		return doctorCommand(args[1:])
	case "diff":
		return diffCommand(args[1:])
	case "verify":
		return verifyCommand(args[1:])
	case "cp", "copy":
		return cpCommand(args[1:])
	case "check":
		return checkCommand(args[1:])
	case "scan":
		return scanCommand(args[1:])
	case "redact":
		return redactCommand(args[1:])
	case "rekey":
		return rekeyCommand(args[1:])
	case "sync":
		return syncCommand(args[1:])
	case "__clearclip": // скрытый воркер отложенной очистки буфера (get --clear-after)
		return clearClipWorker(args[1:])
	case "completion":
		return completionCommand(args[1:])
	case "__complete": // скрытый бэкенд shell-дополнения (sec completion …)
		return completeCommand(args[1:])
	case "log":
		return logCommand(args[1:])
	case "ls", "list":
		return lsCommand(args[1:])
	case "find", "search":
		return findCommand(args[1:])
	case "rm":
		return rmCommand(args[1:])
	case "run":
		return runCommand(args[1:])
	case "export":
		return exportCommand(args[1:])
	case "import":
		return importCommand(args[1:])
	case "push":
		return pushCommand(args[1:])
	case "info":
		return infoCommand(args[1:])
	default:
		die("неизвестная команда %q (sec --help)", args[0])
		return 2 // die() уже вызвал os.Exit; return для компилятора
	}
}
