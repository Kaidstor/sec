# sec share — одноразовые ссылки на секреты

## Контекст

Нужен способ передать секрет человеку по ссылке: получатель открывает URL, видит значение один раз (или в течение TTL 1–7 дней), после — ссылка мертва. Создание ссылок — через CLI `sec`, настроенный на свой домен с токеном. Делиться можно и секретами из стора, и **произвольными значениями** (stdin или файл с диска). Сервер — новый компонент (в репо его нет), деплой на хост `my-vpn` (`/app`), домен **share.kaidstor.ru** (поддомен создаётся через Timeweb API, токен — `sec get home-kai/TIMEWEB_TOKEN`).

**Ключевое архитектурное решение — zero-knowledge**: CLI шифрует значение локально случайным 32-байтным ключом (AES-256-GCM — единственный AEAD, который умеет WebCrypto), на сервер уходит только шифротекст. Ключ живёт в URL-фрагменте и серверу не отправляется:

```
https://share.kaidstor.ru/s/<base62-id-22симв>#<base64url-key-43симв>
```

Страница раскрытия расшифровывает в браузере. Сервер и его админ физически не могут прочитать секрет — даже имя файла едет внутри шифротекста.

**Защита от превью-ботов**: `GET /s/<id>` отдаёт статичную страницу всегда (существование секрета не проверяется — нет оракула, ничего не сгорает). Секрет забирается только `POST …/claim` по клику «Показать».

**Шаг 0 (сразу после утверждения плана)**: создать поддомен share.kaidstor.ru через Timeweb API (пользователь попросил явно; DNS разойдётся, пока пишется код). Квирки API — в notes/deploy.sh: поддомен создаётся POST-ом на родительский домен, A-запись — на родительском с FQDN в поле subdomain; токен только через stdin-конфиг curl.

## Новые команды CLI — итоговая поверхность

```
sec share <proj>/<KEY> [-e env] [--ttl 24h] [--multi]   ссылка на секрет из стора (в т.ч. файловый/бинарный)
sec share - [--ttl …] [--multi]                          произвольное значение: pipe или скрытый ввод с терминала
sec share --file <путь> [--ttl …] [--multi]              произвольный файл с диска (имя и права едут внутри шифротекста)
sec share ls                                             свои активные ссылки: id, создана, истекает, once/multi, просмотров
sec share revoke <id|url>                                досрочно погасить ссылку
sec share setup <url> [--forget]                         подключить сервер: токен скрытым вводом, хранится в сторе sec
```

Примеры:

```bash
sec share whois/DB_PASSWORD                  # → https://share.kaidstor.ru/s/<id>#<key>  (одноразовая, 24h)
sec share infra/server.p12 --ttl 3d          # файловый секрет, получатель скачает с исходным именем
openssl rand -hex 32 | sec share -           # ad-hoc значение, в стор не попадает
sec share --file ~/kube.yaml --multi --ttl 7d
```

По умолчанию ссылка одноразовая с TTL 24h (страховка, если никто не открыл); `--ttl` 1h…168h; `--multi` — многоразовая до истечения TTL. Сгорает по первому из событий.

## Этап 1. Сервер — `server/` (отдельный Go-модуль, stdlib-only, CGO_ENABLED=0)

Один пакет `main`, плоско:

| Файл | Содержимое |
|---|---|
| `go.mod` | `module github.com/kaidstor/sec/server`, go 1.26.0, без require |
| `main.go` | env-конфиг; сабкоманды: `serve` (дефолт), `token add\|ls\|rm <name>`, `version` |
| `server.go` | `Server{st, tokens, rl, maxBlob, maxTTL}`, `Mux() *http.ServeMux` (паттерны Go 1.22+: `"POST /api/v1/secrets"`, `r.PathValue`), хендлеры |
| `storage.go` | `Storage{dir, mu sync.Mutex}`: Save/Claim/List/Delete/Reap |
| `tokens.go` | tokens.json: `Issue/Verify/Remove/List`; сравнение — `subtle.ConstantTimeCompare` |
| `ids.go` | `NewID()` — 16 rand bytes → чистая `base62(b []byte) string` (кодека в проекте нет) |
| `ratelimit.go` | per-IP token bucket на claim, инжектируемые часы |
| `reveal.html` + `embed.go` | страница раскрытия, `go:embed` |

Конфиг (env, всё с дефолтами): `SEC_SHARE_ADDR=:8080`, `SEC_SHARE_DATA=/data`, `SEC_SHARE_MAX_BLOB=8388608`, `SEC_SHARE_MAX_TTL=168h`, `SEC_SHARE_REAP_EVERY=1m`. Лимит 8 MiB не случаен: максимальный файловый секрет стора 4 MiB (`maxFileSecret`, cmd_secrets.go:27) × base64 в JSON-конверте ≈ 5.6 MiB.

### Формат share-блоба (создаёт CLI; сервер хранит непрозрачно, проверяет только магию)

```
0..8   magic ASCII "secshare"
8      версия 0x01
9..21  nonce AES-GCM (12 байт, crypto/rand)
21..   ciphertext AES-256-GCM (тег в хвосте);  AAD = первые 9 байт
```

Plaintext — JSON-конверт: `{"v":1,"type":"text"|"file","filename":"…","mode":"0644","data":<base64>}`. `data` — всегда `Secret.Bytes()`; filename/mode — из `Meta.Filename`/`Meta.FileMode` при `IsFile()`.

### HTTP API

Всё под `/api/` и `/s/` — `Cache-Control: no-store`; ошибки `{"error":"…"}`; id валидируется `^[0-9A-Za-z]{1,64}$` до обращения к диску.

| Метод/путь | Auth | Ответы |
|---|---|---|
| `POST /api/v1/secrets` `{blob, ttl(сек), once}` | Bearer | 201 `{id, expiresAt}`; 400/401/413; ttl>168h молча капается (честный expiresAt в ответе) |
| `GET /s/{id}` | нет | 200 reveal.html всегда |
| `POST /api/v1/secrets/{id}/claim` | нет | 200 `{blob, once}`; 404 (нет/забран/протух — не различать); 429 |
| `GET /api/v1/secrets` | Bearer | 200 — только записи своего tokenName |
| `DELETE /api/v1/secrets/{id}` | Bearer | 204; 404 (нет или чужой — не различать) |
| `GET /healthz` | нет | 200 |

### Data-dir и клейм

```
/data/tokens.json                    {"v":1,"tokens":[{name, sha256, createdAt}]}
/data/secrets/<sha256(id)hex>.json   {"v":1, id, blob, once, tokenName, createdAt, expiresAt, claims}
/data/claimed/                       переходная зона one-time
```

Запись — только tmp + `os.Rename` (паттерн `store.Save`). tokens.json перечитывается на каждый auth — `token add` через `docker exec` работает без рестарта. Токен `sst_<base64url 32 байта>`, печатается один раз, хранится только хэш.

`Claim(id)` под мьютексом: протух → удалить, 404; once → **`os.Rename` в `claimed/` = атомарный клейм** (проигравший получает ENOENT → 404; страхует и окно двойного контейнера при деплое), ответ из памяти, файл из claimed/ удалить после ответа (если ответ оборвался — не реанимировать); multi → `claims++` best-effort. Reaper: тикер, чистит протухшие, `claimed/` старше часа, осиротевшие `*.tmp`. Время — только `time.Now().UTC()`, RFC3339.

### reveal.html

Один файл без внешних ресурсов, палитра/тема дословно из корневого `sec.html` (light/dark). Кнопка «Показать секрет» → JS: ключ из `location.hash`, POST claim, проверка magic/версии, `crypto.subtle.decrypt({name:"AES-GCM", iv:nonce, additionalData:header9})`; text → `<pre>` + «Скопировать»; file → Blob + `<a download>`. Ошибка: «ссылка не существует, уже открыта или истекла». Заголовки: CSP `default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'`, `Referrer-Policy: no-referrer`, `X-Robots-Tag: noindex` + `<meta name="robots" content="noindex">`.

### Тесты (stdlib, httptest)

ids (алфавит/длина/уникальность/вектор); storage — **double-claim: 32 горутины, ровно один успех**, reap; tokens (в файле только хэш); server_test — 401, once: 200→404, multi: два 200 + claims=2, кап TTL, 413, ls только своё, revoke чужого 404, `GET /s/<нет>` → 200; ratelimit.

## Этап 2. CLI

### Новый пакет `cli/internal/share/`

- `blob.go`: `Envelope{V, Type, Filename, Mode string, Data []byte}`, `NewKey`, `Encode`, `Decode` (crypto/aes из stdlib — vendor не трогается).
- `client.go`: `Client{BaseURL, Token, HC}` (таймаут 30s): `Create(blob, ttl, once) (id, expiresAt, err)`, `List`, `Revoke`; 401 → «токен не принят — sec share setup».
- Тесты: round-trip текст/файл, порча байта, golden-заголовок; client — против httptest-фейка.

### `cli/internal/command/cmd_share.go` — `shareCommand(args []string) int`

Диспетчер: `setup`/`ls`/`revoke` — сабкоманды; `-` — stdin; `--file` без ref — файл с диска; иначе аргумент = ref.

- **`sec share <proj>/<KEY> [--ttl 24h] [--multi] [-e env]`**: `splitArgs`+`addEnvFlag`+`resolveKeyRef`; TTL — существующий `parseHumanDuration` (cmd_meta.go:23), валидация 1h–168h, дефолт 24h; чтение **только через `st.Lookup`** (store.go:323 — иначе сломаются link/extend); бинарные/файловые секреты разрешены (в отличие от `get --once` — они едут шифроблобом, не в терминал). Вывод: URL + строка «одноразовая ссылка, сгорит при первом открытии или <локальное время> (24h)». `audit.Record("share", proj+"/"+key, "→ host, id, ttl, once")` — **ключ/фрагмент в аудит не пишется никогда**.
- **`sec share -`** (ad-hoc значение): pipe → читается stdin целиком; TTY → скрытый ввод (как токен в setup). Значение в стор не попадает, конверт `type:"text"`; аудит-target — `(stdin)`.
- **`sec share --file <путь>`** (ad-hoc файл): сырые байты с диска, конверт `type:"file"` с `filename` = basename и `mode` из `os.Stat` — оба уходят только внутри шифротекста; аудит-target — basename. Лимит тот же, что у файловых секретов стора (4 MiB, `maxFileSecret`).
- **`sec share setup <url> [--forget]`**: токен скрытым вводом/stdin (не argv); проверить `List()` до сохранения; записать под `store.Lock()` в проект-константу `_share` (ключи `URL`, `TOKEN`). `_share` не проходит `projRe` (router.go:20 — первый символ буквенно-цифровой) — имя само собой зарезервировано, пользователь не может его трогать через set/rm; поэтому `--forget` — единственный способ удалить. Env-переопределения `SEC_SHARE_URL`/`SEC_SHARE_TOKEN` побеждают стор (и дают e2e без Keychain).
- **`sec share ls`**: id, создана, истекает (локальное время), once/multi, просмотров + напоминание «URL восстановить нельзя — ключ существовал только в момент создания».
- **`sec share revoke <id|url>`**: id вырезается между `/s/` и `#`.

### Правки существующих файлов

- `router.go`: `case "share"`; блок в `const usage` (~стр. 228–344) + `SEC_SHARE_URL/TOKEN` в env-секцию.
- `completion.go`: `"share"` в `completionSubcommands` (стр. 22–28); `completionFlags["share"]`; спец-кейс первого аргумента (`setup|ls|revoke` + ref-кандидаты) — `share` в `refCommandSet` не добавлять. Существующие тесты точный состав списков не ассертят — изменения аддитивны.
- Тесты: completion-кейсы; чистые функции cmd_share (TTL-валидация, id из URL, нормализация URL).

## Этап 3. Деплой — `server/{Dockerfile,compose.yml,deploy.sh}` по образцу `~/Projects/own/notes/`

- **Dockerfile**: build `golang:1.26-alpine`, `CGO_ENABLED=0 go build -trimpath -ldflags "-s -w"`; рантайм `alpine` (шелл нужен для `docker exec … token add`); `VOLUME /data`.
- **compose.yml**: image `sec-share:latest`, `./data:/data`, сеть `vpn` (external), traefik-labels: ``Host(`share.kaidstor.ru`)``, `entrypoints=websecure`, `certresolver=myresolver`, port 8080.
- **deploy.sh**: копия notes/deploy.sh с заменами: `SSH_HOST=my-vpn`, `REMOTE_PATH=/app/sec-share`, `DOMAIN=share.kaidstor.ru`, `SUBDOMAIN=share`, `SERVER_IP=82.97.248.187`; упрощение — `sec export` не нужен (у сервера нет .env-секретов, токены в data-dir), едет только compose.yml; ensure_dns/wait_dns/build→save→rsync→load/healthcheck — как в образце.
- Первый запуск: `./deploy.sh` → `ssh my-vpn docker exec sec-share sec-share token add kai` → локально `sec share setup https://share.kaidstor.ru`.

## Этап 4. Релиз и документация

- `release.sh`: добавить гейт для server/ (`gofmt -l`, `go vet ./...`, `go test ./...`) — сейчас проверяется только cli/. `.goreleaser.yaml` не трогать (сервер едет докером).
- `README.md`: оговорка к тезису «секреты не покидают машину» — share отправляет наружу только шифротекст, ключ живёт в URL-фрагменте и на сервер не уходит. `cli/README.md` («Модель угроз»: сервер видит размер/время/IP, не значение; **URL целиком = секрет**; превью-боты не сжигают — клейм только POST), `SKILL.md` (сценарий «передать секрет человеку»), `sec.html` (карточка share). Raycast — не в v1.

## Порядок и верификация

1. Шаг 0: поддомен через Timeweb API.
2. Сервер послойно (ids→tokens→storage→server→reveal), каждый слой с тестом; `go test ./...` в server/.
3. CLI (blob→client→cmd_share→router/completion); `go test ./...` в cli/; `just check`.
4. **E2E локально**: `SEC_SHARE_DATA=/tmp/ssd go run . serve` + `token add dev` → `SEC_SHARE_URL=http://localhost:8080 SEC_SHARE_TOKEN=… sec share demo/KEY`; `curl -X POST …/claim` дважды (200→404); **открыть ссылку в браузере — обязательная ручная сверка WebCrypto↔Go (nonce/AAD)**; файловый секрет — скачивание с исходным именем.
5. Деплой на my-vpn, `token add`, `sec share setup`, смок через прод: создать→открыть→повторно 404; `sec share ls`/`revoke`.
6. Доки, release.sh.

## Риски

- Double-claim — мьютекс + атомарный rename, тест на 32 горутинах.
- Потеря data-dir — активные ссылки 404, утечки нет (шифротексты без ключей бесполезны); сознательно не бэкапится.
- `_share` виден в голом `sec ls` — в v1 принять (честно).
- `share ls` не показывает URL — это следствие zero-knowledge, задокументировать.
- Версионирование зашито везде (байт в блобе, `v` в конверте и файлах) — формат можно менять без слома.
