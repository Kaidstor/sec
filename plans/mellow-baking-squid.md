# Реорганизация `sec/cli`: плоский `package main` → пакеты

## Context

`cli/` — это ~30 плоских `.go`-файлов в одном `package main`. На одном уровне
перемешаны три слоя: доменная логика (хранилище, крипто, keyring, totp,
fingerprint), инфраструктура (audit, ввод, буфер обмена) и CLI-обработчики
команд (`cmd_*.go`, роутер). Часть файлов внутри себя мешает алгоритм с командой
(`fingerprint.go` = HMAC + `diff`/`verify`; `backup.go` = крипто + `backup`/`restore`;
и т.п.). Из-за этого тяжело понять, где границы и что от чего зависит.

Цель (выбран вариант «полное разбиение на пакеты»): вынести чистую доменную
логику в `internal/`-пакеты, весь CLI-слой — в `internal/command`, оставить
`main.go` тонким. Верхний уровень скилла (`SKILL.md`, `sec.html`, `bin/`) не
трогаем; `sec.sh` правим **только** одной функциональной строкой (иначе реорг
ломает пересборку — см. ниже).

Базовая линия сейчас зелёная: `go build`, `go vet ./...`, `go test ./...`,
`gofmt -l` — всё чисто. Модель данных **уже экспортирована** (`Store`, `Secret`,
`Version`, `Meta` с заглавными полями) — это сильно сокращает правки.

## Целевое дерево

```
cli/
  main.go                     // package main: только func main() → command.Run(os.Args[1:])
  go.mod  go.sum  justfile  .gitignore  README.md
  internal/
    store/      // модель, крипто (XChaCha20), персист, links/extends, merge, addressing, fingerprint
    keyring/    // мастер-ключ: Load/FilePath/OSWrite + build-tagged osKeyring_{darwin,linux,other}
    backup/     // переносной бэкап: Seal/Open (Argon2id+XChaCha) — только крипто
    totp/       // Code (RFC 6238)
    dotenv/     // Parse/Line
    audit/      // Record/Read/Entry (JSONL рядом со стором)
    command/    // ВСЕ *Command, usage, роутер Run, ввод, .sec-конфиг, scan/render/rekey/sync, ref-парсинг
    infisical/  // уже есть, не трогаем
```

Граф зависимостей (ацикличен, проверено):
`main → command → {store, keyring, backup, totp, dotenv, audit, infisical}`,
`store → keyring`, `audit → store`. Листья: keyring, totp, dotenv, backup, infisical.

Модуль — `github.com/kaidstor/sec`, поэтому импорты вида
`github.com/kaidstor/sec/internal/store` и т.д.

## Пакеты: что переезжает и что экспортируется

Правило именования: приватный идентификатор, который пересекает границу пакета,
делаем экспортным (заглавная буква); те, что остаются внутри — не трогаем.
Компилятор + тесты ловят пропуски.

### `internal/keyring` (из `keyring.go`, `keyring_darwin/linux/other.go`)
- Файлы `keyring_*.go` (build-tagged, функции `osKeyring*`) переносим **как есть**,
  оставляя их неэкспортными.
- Экспортное API в `keyring.go`: `Load(create)` (было `loadKey`), `FilePath()`
  (было `keyFilePath`), тонкая обёртка `OSWrite(hex)` → `osKeyringWrite`
  (нужна `rekey`). При надобности добавить `OSName/OSAvailable/OSRead`-обёртки.
- Зависимости: только stdlib. Лист.

### `internal/store` (из `store.go` + чистая `fingerprint()` из `fingerprint.go`)
Ядро. Экспортируем поверхность, которая уже пересекает границу (подтверждено
grep'ом мест вызова):
- Типы: `Origin` (было `origin`), `OriginOwn/OriginRef/OriginExtend`.
- Функции: `Open`(было `openStore`), `Save`, `Lock`, `Path`, `Merge`(`mergeStores`),
  `Put`(`putSecret`), `Fingerprint`(`fingerprint`), `MaskValue`, `SortedKeys`,
  `Now`; addressing: `ProjKey`(`storeProj`), `BaseAndEnv`, `RefToCLI`,
  `RefToCLIProj`. `splitRef`, `encrypt`, `decrypt` — остаются приватными (нужны
  только внутри store).
- Методы `*Store`: `Project`, `Prune`, `ResolveSecret`, `Lookup`, `EffectiveKeys`,
  `AddExtend`, `RemoveExtend`, `Referrers`, `ProjectReferrers`, `Extenders`.
  `collectKeys`, `extendReaches` — приватные.
- Методы `Secret`: `Undo`, `Redo`, `Forget`.
- **Убрать из store:** `mustEditable` и `editBlock` уезжают в `command` (в них
  `die` и строки-подсказки `sec set …` — это CLI-слой). После этого store не
  ссылается на `die` вообще. `Open` продолжает звать `keyring.Load`.

### `internal/backup` (только `sealBackup`/`openBackup` из `backup.go`)
- `Seal`(`sealBackup`), `Open`(`openBackup`) + консты Argon2. Только x/crypto.
- `readPassphrase` и команды `backup`/`restore` → в `command`.

### `internal/totp` / `internal/dotenv` (листья)
- `totp`: `Code`(`totpCode`). `dotenv`: `Parse`(`parseDotenv`), `Line`(`dotenvLine`).

### `internal/audit` (из `audit.go`)
- `Record`(`audit`), `Read`(`readAudit`), тип `Entry`(`auditEntry`, поля уже
  экспортны). `auditPath`/`caller` — приватные. Путь берёт из `store.Path()`
  (одна сторона, цикла нет), свой `now()` (одна строка).

### `internal/command` (всё остальное)
Сюда переезжают: `main.go`-хелперы роутинга/ссылок (`die`, `resolveRef`,
`resolveProj`, `resolveKeyRef`, `resolveServiceProj`, `collectPositionals`,
`mustSecret`, `selectKeys`, `addEnvFlag`, `splitArgs`, `cwdProject`, regex'ы,
`usage`), все `cmd_*.go`, `input.go`, `clipclear.go`, `render.go`, `scan.go`,
`sync.go`, `rekey.go`, `fingerprint.go`-команды (`diffCommand`/`verifyCommand`),
`backup.go`-команды + `readPassphrase`, `cmd_check.go` (.sec-конфиг,
`resolvedEnv`/`refService`). Плюс переехавшие сюда `mustEditable`/`editBlock`
(теперь свободные функции над `*store.Store`, зовут `store.RefToCLI`, `st.Lookup`,
`store.OriginExtend`), `fmtTime` (чистая презентация времени).
- Новый экспорт: `Run(args []string) int` — держит `switch args[0]` (бывший
  роутер из `main.go`) и печать `usage`. Все `*Command`-функции остаются
  неэкспортными внутри пакета.
- Внутри — массовая замена вызовов на квалифицированные: `openStore`→`store.Open`,
  `saveStore`→`store.Save`, `lockStore`→`store.Lock`, `storePath`→`store.Path`,
  `now`→`store.Now`, `sortedKeys`→`store.SortedKeys`, `maskValue`→`store.MaskValue`,
  `storeProj`→`store.ProjKey`, `baseAndEnv`→`store.BaseAndEnv`,
  `refToCLI`→`store.RefToCLI`, `refToCLIProj`→`store.RefToCLIProj`,
  `putSecret`→`store.Put`, `mergeStores`→`store.Merge`, `fingerprint`→`store.Fingerprint`,
  `audit(`→`audit.Record(`, `loadKey`→`keyring.Load`, `keyFilePath`→`keyring.FilePath`,
  `osKeyringWrite`→`keyring.OSWrite`, `totpCode`→`totp.Code`,
  `parseDotenv`→`dotenv.Parse`, `dotenvLine`→`dotenv.Line`,
  `sealBackup`→`backup.Seal`, `openBackup`→`backup.Open`; методы стора → заглавные
  (`st.lookup`→`st.Lookup`, `.undo()`→`.Undo()` и т.д.).
- Типы стора у команд уже используются как `Store`/`Secret` — станут
  `store.Store`/`store.Secret`/`store.Version`/`store.Meta`.

### `cli/main.go` (тонкий)
```go
package main
import ("os"; "github.com/kaidstor/sec/internal/command")
func main() { os.Exit(command.Run(os.Args[1:])) }
```
Комментарий-«карта модулей» из шапки старого `main.go` переписать под новое
дерево (в `main.go` и/или README `cli/`).

## Тесты — переселить по пакетам

Тесты сейчас в `package main`; их надо разнести и часть **разбить**:
- `store_test.go`, `link_test.go` → `internal/store` (переименовать вызовы на
  экспортные: `putSecret`→`store.Put` и т.п.; `storeWith`-хелпер тоже сюда).
- `backup_test.go` → `internal/backup`.
- `totp_test.go` → `internal/totp`; `dotenv`-часть `dotenv_test.go` → `internal/dotenv`.
- `feature_test.go` **разбить**: `TestFingerprintKeyed`/`TestStoreProjEnv`/
  `TestMergeStores` → store; `TestParseHumanDuration`/`TestResolveExpiresAt`/
  `TestDueAt` (хелперы `cmd_meta.go`) и `TestParseSecFile` (.sec) → command.
- `TestMergedEnv` из `dotenv_test.go` (тестит `mergedEnv` из `cmd_project.go`) →
  command.
- Проще всего внешние тест-пакеты (`store_test`, `command_test`) с обращением к
  экспортному API; где тест лезет в приватное — тест-файл в том же пакете.

## Обязательная правка вне `cli/`: `sec.sh` (одна строка логики)

`sec.sh` определяет «пора пересобрать» перебором **только** `"$SRC"/*.go`
(верхний уровень). После реорга почти весь код уедет в `internal/*/`, и правки
там перестанут триггерить пересборку — обёртка будет гонять устаревший бинарь.
Заменить glob верхнего уровня на рекурсивный поиск, напр.:
```sh
if [ -n "$(find "$SRC" -name '*.go' -newer "$BIN" -print -quit 2>/dev/null)" ]; then
  needs_build=1
fi
# плюс отдельная проверка "$SRC/go.mod" -nt "$BIN"
```
(Это заодно чинит уже существующий латентный баг: правки в `internal/infisical`
и сейчас не отслеживаются.) `justfile` (`go build -o ../bin/sec .`, `go vet ./...`)
и сборка в `sec.sh` (`go build -o "$BIN" .`) с подпакетами работают без изменений.

`go.mod` (`go 1.26.0` при локальном go 1.23.5) сейчас собирается — не трогаем.

## Порядок работ

1. Листья: `keyring`, `totp`, `dotenv`, `backup` (перенести файлы, сменить
   `package`, экспортировать API, build-tags сохранить).
2. `store` (перенести `store.go` + `fingerprint()`; выкинуть `mustEditable`/`editBlock`;
   экспортировать поверхность; `Open` зовёт `keyring.Load`).
3. `audit` (импорт `store.Path`).
4. `command` (все прочие файлы; `Run`-роутер; ре-врайринг вызовов; локальные
   `mustEditable`/`editBlock`/`readPassphrase`/`fmtTime`).
5. Тонкий `main.go`.
6. Разнести/разбить тесты.
7. Починить staleness-glob в `sec.sh`.

## Проверка (end-to-end)

```sh
cd cli
gofmt -l .                 # пусто
go vet ./...               # чисто
go build ./...             # чисто
go test ./...              # все пакеты ok (store/keyring/backup/totp/dotenv/command/…)
```
Затем дым-тест реального бинаря через обёртку на временном сторе (значения
не светятся):
```sh
export SEC_STORE=$(mktemp -d)/store.enc SEC_KEY=$(openssl rand -hex 32)
./sec.sh info
printf 'val123456\n' | ./sec.sh set demo/TOKEN --stdin
./sec.sh ls -l
./sec.sh get demo/TOKEN --peek
./sec.sh get demo/TOKEN --fingerprint
```
И проверить, что реорг не сломал пересборку: `touch cli/internal/store/store.go`
→ следующий `./sec.sh info` должен пересобрать бинарь (а не молча запустить
старый). Финально — `just build` (или `sec.sh`) кладёт свежий `bin/sec`.

Критерий приёмки: те же зелёные `build/vet/test/gofmt`, что и на базовой линии,
плюс совпадающее поведение дым-тестовых команд.
