#!/usr/bin/env bash
# Выпуск новой версии sec в Homebrew.
#
# Версия задаётся git-тегом vX.Y.Z: пуш тега запускает .github/workflows/release.yml,
# goreleaser собирает бинарники (darwin/linux × amd64/arm64), создаёт GitHub Release
# и обновляет формулу в tap-репозитории → `brew install/upgrade kaidstor/tap/sec`.
# Здесь мы только валидируем состояние, считаем следующую версию, ставим и пушим тег.
#
# Использование:
#   ./release.sh              # patch: 0.1.0 → 0.1.1 (по умолчанию)
#   ./release.sh patch|minor|major
#   ./release.sh v1.2.3       # явная версия
#   ./release.sh -n minor     # dry-run: показать, что будет, без тега и пуша
#
# Требования: git, ветка main, чистое дерево, синхрон с origin, зелёные тесты.
# gh и goreleaser — опциональны (следим за прогоном / локальный goreleaser check).
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")" # корень репозитория (здесь .goreleaser.yaml, .github/)

die() { printf 'release.sh: %s\n' "$*" >&2; exit 1; }

# --- разбор аргументов ---
DRY=0
BUMP="patch"
for a in "$@"; do
  case "$a" in
    -n|--dry-run)      DRY=1 ;;
    -h|--help)         sed -n '2,18p' "$0"; exit 0 ;;
    patch|minor|major) BUMP="$a" ;;
    v[0-9]*)           BUMP="$a" ;;
    *) die "неизвестный аргумент '$a' (patch|minor|major|vX.Y.Z|-n|-h)" ;;
  esac
done

command -v git >/dev/null || die "нужен git"

# --- предполётные проверки ---
[ "$(git rev-parse --is-inside-work-tree 2>/dev/null)" = "true" ] || die "не git-репозиторий"

BRANCH="$(git symbolic-ref --short HEAD 2>/dev/null || echo)"
[ "$BRANCH" = "main" ] || die "релиз только с ветки main (сейчас: ${BRANCH:-detached HEAD})"

git diff --quiet && git diff --cached --quiet \
  || die "есть незакоммиченные изменения — сначала закоммить и запушь"

echo "→ синхронизация с origin…"
git fetch --quiet origin || die "git fetch не удался"
UP="$(git rev-parse --abbrev-ref '@{u}' 2>/dev/null || echo)"
[ -n "$UP" ] || die "у main нет upstream — git push -u origin main"
[ "$(git rev-parse @)" = "$(git rev-parse '@{u}')" ] \
  || die "main разошёлся с origin ($UP) — сначала git push / git pull"

# --- вычисление следующей версии ---
LATEST="$(git tag --list 'v*' --sort=-v:refname | head -1)"
LATEST="${LATEST:-v0.0.0}"
if [[ "$BUMP" == v* ]]; then
  NEXT="$BUMP"
else
  IFS=. read -r MA MI PA <<<"${LATEST#v}"
  case "$BUMP" in
    patch) PA=$((PA + 1)) ;;
    minor) MI=$((MI + 1)); PA=0 ;;
    major) MA=$((MA + 1)); MI=0; PA=0 ;;
  esac
  NEXT="v${MA}.${MI}.${PA}"
fi

[[ "$NEXT" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "неверная версия '$NEXT' (ожидаю vX.Y.Z)"
git rev-parse "$NEXT" >/dev/null 2>&1 && die "тег $NEXT уже существует"

echo "  версия: $LATEST → $NEXT"

# --- gofmt / vet / test ---
echo "→ проверки (gofmt, vet, test)…"
(
  cd cli
  bad="$(gofmt -l . | grep -v '^vendor/' || true)"
  [ -z "$bad" ] || { printf '%s\n' "$bad"; die "gofmt: есть неотформатированные файлы (gofmt -w cli)"; }
  go vet ./... || die "go vet упал"
  go test ./... || die "тесты упали"
) || exit 1

# --- опциональный локальный goreleaser check ---
if command -v goreleaser >/dev/null 2>&1; then
  echo "→ goreleaser check…"
  goreleaser check || die "goreleaser check не прошёл (.goreleaser.yaml)"
fi

if [ "$DRY" -eq 1 ]; then
  echo "[dry-run] поставил бы тег $NEXT и запушил 'origin $NEXT' — релиз не запущен"
  exit 0
fi

# --- тег и пуш (это и запускает релиз) ---
git tag -a "$NEXT" -m "release $NEXT"
git push origin "$NEXT"
echo "✓ тег $NEXT запушен — GitHub Actions собирает релиз"

# --- по возможности проследить за прогоном ---
if command -v gh >/dev/null 2>&1; then
  REPO="$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null || echo)"
  echo "→ жду запуск workflow release…"
  RUN=""
  for _ in 1 2 3 4 5 6; do
    sleep 5
    RUN="$(gh run list --workflow release.yml --event push --limit 1 --json databaseId -q '.[0].databaseId' 2>/dev/null || echo)"
    [ -n "$RUN" ] && break
  done
  if [ -n "$RUN" ]; then
    gh run watch "$RUN" --exit-status ${REPO:+--repo "$REPO"} \
      && echo "✓ релиз $NEXT готов — brew install/upgrade kaidstor/tap/sec" \
      || die "workflow упал — смотри 'gh run view $RUN --log-failed'"
  else
    echo "  (не нашёл прогон — проверь вручную: gh run list --workflow release.yml)"
  fi
else
  echo "  gh не установлен — следи за релизом на GitHub → Actions"
fi
