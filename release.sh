#!/usr/bin/env bash
# Выпуск новой версии CLI sec в Homebrew (приложение релизится отдельно —
# app/release.sh). Тонкая обёртка над общим релизным скриптом Go-CLI — вся
# логика в ../_release/go-release.sh (проверки, следующая версия, тег, ожидание
# workflow release.yml с goreleaser).
#
#   ./release.sh [patch|minor|major|vX.Y.Z] [-n]   # -h — справка
#   INSTALL=1 ./release.sh                         # и обновить CLI на этой машине
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

APP_NAME=sec
GO_MODULES="cli server"

source ../_release/go-release.sh
