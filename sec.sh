#!/usr/bin/env bash
# Самозагружающийся entrypoint для CLI sec, поставляемого вместе со скиллом.
# Собирает Go-бинарь из ./cli при первом запуске (и когда исходники изменились),
# затем запускает его. Нужен Go в PATH. Подробности — cli/README.md.
set -euo pipefail

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$SKILL_DIR/cli"
BIN="$SKILL_DIR/bin/sec"

needs_build=0
if [ ! -x "$BIN" ]; then
  needs_build=1
else
  # Исходники разложены по пакетам (cli/*.go и cli/internal/**), поэтому ищем
  # любой .go/go.mod/go.sum новее бинаря рекурсивно, а не только в корне cli/.
  if [ -n "$(find "$SRC" \( -name '*.go' -o -name 'go.mod' -o -name 'go.sum' \) -newer "$BIN" -print -quit 2>/dev/null)" ]; then
    needs_build=1
  fi
fi

if [ "$needs_build" -eq 1 ]; then
  if ! command -v go >/dev/null 2>&1; then
    echo "sec: для сборки нужен Go (https://go.dev/dl). Либо собери вручную:" >&2
    echo "          cd '$SRC' && go build -o '$BIN' ." >&2
    exit 127
  fi
  mkdir -p "$SKILL_DIR/bin"
  # Если папка — git-чекаут с тегами, проставим версию из git (иначе останется "dev").
  VERSION="$(git -C "$SKILL_DIR" describe --tags --always --dirty 2>/dev/null || true)"
  if [ -n "$VERSION" ]; then
    ( cd "$SRC" && go build -ldflags "-X github.com/kaidstor/sec/internal/command.version=$VERSION" -o "$BIN" . ) \
      || { echo "sec: сборка не удалась" >&2; exit 1; }
  else
    ( cd "$SRC" && go build -o "$BIN" . ) || { echo "sec: сборка не удалась" >&2; exit 1; }
  fi
fi

exec "$BIN" "$@"
