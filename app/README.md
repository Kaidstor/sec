# sec app — desktop-клиент

Tauri-приложение поверх CLI `sec`: список и поиск секретов, копирование через
сам CLI (`--clip` — значения в JS-слой не попадают), peek/история/undo-redo,
добавление и генерация, share-ссылки на один ключ и на пак целиком
(`--all`/`--only`), отзыв активных ссылок, переключаемые темы
(дизайн-система kai / sql-kai).

## Требования

- CLI `sec` в PATH или стандартных местах (`/opt/homebrew/bin`, `/usr/local/bin`,
  `~/go/bin`); путь можно переопределить env-переменной `SEC_BIN`.
- Для share — настроенный сервер ссылок (`sec share setup <url>` или
  `SEC_SHARE_URL`/`SEC_SHARE_TOKEN`).

## Разработка

```sh
pnpm install
pnpm tauri dev
```

Приложение наследует окружение процесса: для разработки на тестовом сторе —

```sh
SEC_STORE=/tmp/dev-store.enc SEC_KEY=<hex64> pnpm tauri dev
```

## Сборка

```sh
pnpm tauri build
```

Иконки в `src-tauri/icons` сгенерированы `pnpm tauri icon` из мастер-PNG
(низкополигональный sky-замок с кольцом — семейный стиль со слоном sql-kai).

## Релиз

`./release.sh` — обёртка над общим `../../_release/tauri-release.sh`
(бамп версий, подписанная сборка app+dmg, нотаризация, тег `app-vX.Y.Z` —
линейка `vX.Y.Z` занята релизами CLI, — GitHub-релиз и автобамп каска
`sec-app` в homebrew-tap). Секреты — из sec:

```sh
NOTES="…" sec run sec-app \
  --file TAURI_SIGNING_PRIVATE_KEY=tauri-keys/SEC_APP_PEM -- ./release.sh [версия]
```

`APPLE_ID`/`APPLE_TEAM_ID` — в `.env` (образец: `.env.example`),
`APPLE_PASSWORD` доливает `sec run` (ссылка `sec-app/APPLE_PASSWORD`).
Установка у пользователя: `brew install --cask kaidstor/tap/sec-app`
(CLI `sec` приедет зависимостью), обновление — `brew upgrade --cask sec-app`.
