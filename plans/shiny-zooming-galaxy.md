# sec: сверка и применение env на удалённый хост + `kind: config`

## Контекст

Прод-конфиг `/app/.env.whois` на `10.101.0.21` правился руками (`ssh` + `sudo sed -i`),
потому что через `sec` это сегодня невозможно. Сверка на живых данных: в сторе 22 ключа,
на проде 20, общих 13 — стор и прод разошлись молча, и никто об этом не знал.

Две дыры:

- **`sec diff` сравнивает стор со стором** (два проекта или инстанса). Сверки с env-файлом
  на хосте нет — расхождение не видно, пока не полезешь руками.
- **`sec export --file host:/path` пересобирает файл целиком.** На whois это снесло бы семь
  прод-ключей (`WHOIS_VERSION` от CI, `DOMAINATOR_DB_URL`, `REDIS_URL`, …) и дописало семь
  чужих (`FLEET_*`, `OTEL_*`, `NPM_TOKEN` — переменные CI и elastic-agent). Плюс файл
  root-овый: записи по ssh-stdin без sudo не хватит.

Третья, смежная: любое значение из стора длиной ≥8 символов ловится `scan`/`redact` как
секрет. Для несекретной настройки (`WHOIS_HISTORY_PROVIDERS=whoxy`, URL эндпоинта,
`WHOIS_LOOKUP_CACHE_MAX_SIZE=50000`) это ложное срабатывание, а в `diff`/`deploy` такие
значения удобнее видеть открытым текстом, чем отпечатком.

Источник: `handoff-sec-deploy.md` (03.08.2026). Задачи в YouTrack не заводить — репозиторий личный.

## Итоговая поверхность CLI

```
sec diff <proj> <host>:/path/.env [--sudo] [--only A,B]   сверить стор с env-файлом на хосте
sec diff <proj> ./path/.env                               то же с локальным файлом
sec diff <projA> <projB> | <svc> -e <e1> <e2>             как сейчас, стор ↔ стор

sec deploy [proj] --to <host>:/path/.env [-e env]         применить стор в env-файл (merge)
    --only A,B      только перечисленные ключи
    --sudo          читать/писать под sudo (root-овые прод-конфиги)
    --replace       пересобрать файл целиком (по умолчанию — merge)
    --no-backup     не делать <path>.bak-<ts> на хосте
    --dry-run       показать diff и выйти, ничего не записывая
    --yes           без подтверждения (CI)
    --after '<cmd>' выполнить команду на хосте после записи

sec meta <proj>/<KEY> --kind config    пометить значение несекретной настройкой
sec set  <proj>/<KEY> --kind config    то же при заведении
sec scan   … [--include-config]        вернуть kind: config в поиск утечек
sec redact … [--include-config]        то же для чистки текста
```

Примеры:

```bash
# та самая правка трёх переменных на whois, но без ssh+sed
sec diff whois whois:/app/.env.whois --sudo
sec deploy whois --to whois:/app/.env.whois --sudo --only WHOIS_HISTORY_PROVIDERS,WHOIS_ARCHIVE_CUTOFF_DATE \
  --after 'cd /app && docker compose up whois -d'
```

Вывод сверки — только имена и статусы, значения не раскрываются (кроме `kind: config`):

```
= WHOXY_API_KEY                совпадает
~ WHOIS_HISTORY_PROVIDERS      различаются     стор: whoxy   хост: whoxy,ripe
+ REDIS_URL                    нет на хосте
? DOMAINATOR_DB_URL            только на хосте (в сторе нет)
итого: совпадают 13, различаются 1, нет на хосте 7, только на хосте 7
```

Строка «стор: … хост: …» появляется только у `kind: config`. Код выхода `diff` — 2 при любом
расхождении (как у нынешнего стор↔стор), 0 при полном совпадении.

## Что делаем

### 1. `sec diff <proj> <host>:<path>` — read-only сверка

**Новое: `cli/internal/command/envtarget.go`** — цель «env-файл где-то»:

- `parseEnvTarget(s) envTarget{host, path}` — поверх готового `splitRemoteTarget`
  (`remote.go:19`); не удалённое и `looksLikePath` (`cmd_project.go:505`) → локальный файл.
- `(envTarget).read(sudo) ([]byte, bool, error)` — локально `os.ReadFile`, удалённо
  `ssh host 'sudo -n cat -- <путь>'`. Второй результат — существует ли файл (отсутствие
  не ошибка: для `deploy` это «создадим»).
- `(envTarget).write(sudo, data)`, `.backup(sudo, suffix)`, `.exec(cmd)` — для этапа 2.

**Расширяем `remote.go`**: `sshRun(host, remote string, stdin []byte) ([]byte, error)` —
общий запуск (нынешний `sshWriteFile` ложится на него), плюс `sudoWrap(cmd, sudo)` →
`sudo -n <cmd>`. Пути экранируются готовым `shSingleQuote`; значения ходят только через
stdin/stdout, в argv не попадают — инвариант, который проверяет `remote_test.go`.

**sudo с паролем**: сначала `sudo -n`. Если хост ответил «a password is required» и мы в
терминале — один раз `ssh -t <host> sudo -v` (пользователь вводит пароль сам, sec его не
видит и через себя не пропускает), дальше `sudo -n` работает ~15 минут. Не TTY → внятная
ошибка с подсказкой про NOPASSWD.

**Новое: `cli/internal/command/envdiff.go`** — движок сверки, общий для `diff` и `deploy`:
`compareToFile(storeKeys map[string]store.Secret, fileKV map[string]string, mkey []byte) []entry`
со статусами `same / differ / missingOnHost / onlyOnHost`, плюс рендер и итоговая строка.
Сравнение — по отпечаткам `store.Fingerprint` + `hmac.Equal`, как в нынешнем `diffCommand`
(`fingerprint.go:65`). Разбор файла — `dotenv.Parse`, его warnings уходят в stderr.

**`diffCommand` (`fingerprint.go:22`)**: если второй позиционный — env-цель, уходим в файловый
режим. Бинарные и `kind: file` ключи в сверке не участвуют (в `.env` им не место) — счётчик
пропущенных в stderr, как в `exportCommand` (`cmd_project.go:484`).

### 2. `sec deploy` — merge-применение

**Новое: `cli/internal/dotenv/merge.go`**:

```go
// Merge вписывает значения kv в текст .env, сохраняя порядок строк, комментарии,
// пустые строки и префикс export. Ключи, которых в тексте нет, дописываются в конец.
func Merge(orig string, kv map[string]string) (out string, updated, added []string)
```

Построчно, значения форматируются готовой `dotenv.Line` (`dotenv.go:56`). Сохранять исходный
терминатор строки (`\r\n` на месте) и отсутствие финального перевода строки.
Требование хендоффа №5: без этого каждый деплой переписывает файл целиком и глазами не сверить.

**Новое: `cli/internal/command/cmd_deploy.go`** — `deployCommand`, порядок жёсткий:

1. ключи проекта (`st.EffectiveKeys`, ссылки/наследование разрешены), минус бинарные и
   `kind: file`, минус то, что отсеял `--only`;
2. прочитать целевой файл (нет файла → пустой + предупреждение «будет создан»);
3. напечатать diff движком из п. 1; в `--replace` ключи хоста, которых нет в сторе,
   показываются как `- KEY  будет удалён с хоста` со сводкой «потеряется N ключей»;
4. **пустой diff → «нечего делать», код 0**; `--dry-run` → выйти 0 здесь же;
5. подтверждение `y/N` (`--yes` снимает; нет TTY и нет `--yes` → ошибка с подсказкой);
6. бэкап `cp -p -- <path> <path>.bak-<YYYYMMDD-HHMMSS>` (снимается `--no-backup`);
7. запись: merge-результат → `sudo -n tee <path> > /dev/null` (in-place: владелец, права и
   inode файла сохраняются — в отличие от tmp+mv);
8. `--after` — команда на хосте, её stdout/stderr стримятся пользователю;
9. verify: перечитать файл, сверить отпечатки, «применилось N ключей»; расхождение — код 2.

`audit.Record("deploy", proj, "→ host:path (N ключей)")` — как у `export`. Значения в журнал,
разумеется, не идут.

### 3. `kind: config`

- `store.Secret.IsConfig()` рядом с `IsFile`/`IsBinary` (`store/store.go:76`).
- `collectStoreValues` / `collectBinaryValues` (`scan.go:39`) пропускают такие значения и
  считают их отдельно; в stderr — строка вида «пропущено значений `kind: config`: N
  (искать и их: `--include-config`)», по образцу нынешнего сообщения про `--min`.
  Флаг `--include-config` у `scan` и `redact`.
- `envdiff.go` печатает значения `kind: config` открытым текстом (в остальных случаях —
  только имя и статус).
- `keyDetails` (`store_helpers.go:91`) уже показывает `kind` в `ls -l` — правок не нужно;
  в подсказках флагов `--kind` у `set`/`gen`/`meta` дописать `config`.

### Документация и обвязка

- `router.go`: строка `sec deploy …` в usage, расширенная строка `sec diff`, короткий блок
  про деплой рядом с блоком «Запись по ssh».
- `completion.go`: `deploy` в `completionSubcommands` и `projCommandSet`, флаги `deploy`,
  `--sudo/--only` у `diff`, `--include-config` у `scan`/`redact`.
- `SKILL.md`: две нынешние гочи (`diff` только стор↔стор; `export --file host:path`
  пересобирает файл) заменить на актуальные — `deploy` мержит по умолчанию, `--after`
  обязателен там, где сервис не перечитывает файл сам, `--sudo` для root-овых конфигов,
  `kind: config` вне `scan`.
- `README.md`: пункт про сверку/применение на хост в списке возможностей.
- `docs/deploy.md`: короткая архитектурная заметка (почему merge, а не replace; почему
  `tee` in-place, а не tmp+mv; как устроен sudo без пароля в sec) — по образцу `docs/share.md`.

**Коммиты не делаю**: в дереве лежит незакоммиченная работа владельца (`README.md`,
`SKILL.md`, `cli/internal/command/cmd_project.go`, `docs/file-secrets-and-scan.md`), и мои
правки ложатся поверх тех же файлов. Разбиение на коммиты — за пользователем; предложу
три: `diff`, `deploy`, `kind: config`.

## Проверка

Тесты (`go test ./...` из `cli/`), в стиле нынешних:

- `dotenv/merge_test.go` — порядок строк, комментарии, `export KEY=`, `\r\n`, файл без
  финального перевода строки, дописывание новых ключей в конец, спецсимволы в значении.
- `envdiff_test.go` — все четыре статуса, значения не попадают в вывод для не-`config`,
  для `config` попадают; счётчики итоговой строки.
- `cmd_deploy_test.go` — фейковый `ssh` в `PATH` (приём из `remote_test.go:44`): значение
  не появляется в argv, путь заэкранирован, `--dry-run` ничего не пишет, бэкап делается
  до записи, `--after` выполняется после, `--replace` предупреждает о потере ключей.
- `scan_test.go` — `kind: config` не считается утечкой, с `--include-config` считается.

Живая проверка (руками, на реальном whois — read-only сначала):

```sh
go build ./cmd/... && sec diff whois whois:/app/.env.whois --sudo     # ждём 13 =, 1 ~, 7 +, 7 ?
sec deploy whois --to whois:/app/.env.whois --sudo --dry-run          # тот же diff, записи нет
sec deploy whois --to whois:/tmp/env-probe --only REDIS_URL           # безопасная цель
```
