#!/usr/bin/env bash
# Тонкая обёртка над общим релизным скриптом личных проектов —
# вся логика в ../../_release/tauri-release.sh (версии, тег, GitHub-релиз,
# сборка app+dmg, нотаризация, аплоад артефактов, бамп brew-каска).
#
# Запуск (ключ апдейтера и APPLE_PASSWORD — из sec; tauri build принимает в
# TAURI_SIGNING_PRIVATE_KEY и содержимое, и путь — sec run --file даёт путь):
#   sec run sec-app --file TAURI_SIGNING_PRIVATE_KEY=tauri-keys/SEC_APP_PEM -- ./release.sh
set -euo pipefail
cd "$(dirname "$0")"

APP_NAME=sec-app
PM=pnpm
FORGE=github
WITH_CLI=0 # CLI на Go, релизится отдельно: корневой ./release.sh → goreleaser
# теги vX.Y.Z заняты релизами CLI (goreleaser) — у приложения своя линейка
TAG_PREFIX=app-v
# автобамп Homebrew-каска (version/sha256 + push tap) после публикации
BREW_CASK=../../homebrew-tap/Casks/sec-app.rb

source ../../_release/tauri-release.sh
