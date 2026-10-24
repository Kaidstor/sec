#!/bin/sh
# Дымовой прогон всех команд собранным бинарём во временном каталоге:
#   sh internal/command/testdata/smoke.sh ./sec
# Мастер-ключ — синтетический SEC_KEY, Keychain и настоящий стор не трогаются.
set -u
BIN=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
D=$(mktemp -d)
trap 'rm -rf "$D"' EXIT
export SEC_STORE="$D/store.enc" SEC_KEY_FILE="$D/key" XDG_CONFIG_HOME="$D/cfg" HOME="$D/home"
export SEC_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
export SEC_NO_USAGE=1 SEC_NO_SKILL_SYNC=1 SEC_PASSPHRASE=synthetic-passphrase-123
mkdir -p "$D/home" && cd "$D" || exit 1
fails=0
ok() { # ok <ожидаемый код> <команда…>
  want=$1; shift
  "$@" >"$D/out" 2>"$D/err"; got=$?
  if [ "$got" != "$want" ]; then
    fails=$((fails+1)); echo "FAIL (${got} != ${want}): $*"; cat "$D/out" "$D/err" | sed 's/^/  | /' | head -8
  fi
}
printf 'tok-aaaaaaaa1' | ok 0 "$BIN" set app/TOKEN
printf 'tok-aaaaaaaa2' | ok 0 "$BIN" set app/TOKEN --note n --kind apikey
ok 0 "$BIN" gen app/GEN --len 20
printf 'https://example.invalid' | ok 0 "$BIN" set app/URL --kind config
printf '\000\001\002bin' > blob.bin; ok 0 "$BIN" set app/CERT --from-file blob.bin
printf 'otpauth://totp/x?secret=JBSWY3DPEHPK3PXP' | ok 0 "$BIN" set app/TOTP
ok 0 "$BIN" get app/TOKEN; ok 0 "$BIN" get app/TOKEN --peek; ok 0 "$BIN" get app/TOKEN --fingerprint
ok 0 "$BIN" get app/TOKEN --prev 1; ok 0 "$BIN" get app/CERT --out cert.out; ok 0 "$BIN" get app/TOKEN --json
printf 'tok-aaaaaaaa2' | ok 0 "$BIN" verify app/TOKEN
ok 0 "$BIN" history app/TOKEN; ok 0 "$BIN" history app/TOKEN --json
ok 0 "$BIN" undo app/TOKEN; ok 0 "$BIN" redo app/TOKEN; ok 0 "$BIN" forget app/TOKEN
ok 0 "$BIN" meta app/TOKEN --rotate-every 90d; ok 0 "$BIN" meta app/TOKEN
ok 0 "$BIN" otp app/TOTP
ok 0 "$BIN" ls; ok 0 "$BIN" ls app -l; ok 0 "$BIN" ls --json; ok 0 "$BIN" find TOKEN
ok 0 "$BIN" cp app/TOKEN app2; ok 0 "$BIN" mv app2/TOKEN app2/T2
ok 0 "$BIN" link web/TOKEN app/TOKEN; ok 0 "$BIN" get web/TOKEN; ok 0 "$BIN" unlink web/TOKEN
ok 0 "$BIN" extend web --from app; ok 0 "$BIN" ls web; ok 0 "$BIN" extend web --remove app
ok 2 "$BIN" diff app app2
ok 0 "$BIN" run app --only TOKEN -- sh -c 'test "$TOKEN" = tok-aaaaaaaa2'
ok 0 "$BIN" run app --file CERT -- sh -c 'test -s "$CERT"'
ok 0 "$BIN" export app --file app.env
printf 'A={{ secret "app/TOKEN" }}\n' > t.tpl; ok 0 "$BIN" render t.tpl --file out.txt --proj app
printf 'X=1\nY=2\n' | ok 0 "$BIN" import imp -
printf 'TOKEN=old\n' > host.env; ok 2 "$BIN" diff app ./host.env --only TOKEN
ok 0 "$BIN" deploy app --to ./host.env --only TOKEN --yes
ok 0 "$BIN" diff app ./host.env --only TOKEN
printf 'project: app\nkeys: TOKEN\n' > .sec; ok 0 "$BIN" check app --file .sec
ok 1 "$BIN" scan app.env; ok 0 "$BIN" redact app.env
ok 0 "$BIN" stale; ok 1 "$BIN" doctor; ok 0 "$BIN" info  # doctor: дубль app/TOKEN после cp — ожидаемая находка
ok 0 "$BIN" backup --file bak.enc
printf 'tok-changed-xx' | ok 0 "$BIN" set app/TOKEN
ok 0 "$BIN" restore --file bak.enc; ok 0 "$BIN" restore --file bak.enc --replace
ok 0 "$BIN" sync --file blob.enc; ok 0 "$BIN" sync --file blob.enc
printf 'once-value-1' | ok 0 "$BIN" set app/ONCE; ok 0 "$BIN" get app/ONCE --once; ok 3 "$BIN" get app/ONCE
ok 0 "$BIN" migrate --to-v2; ok 0 "$BIN" get app/TOKEN; printf 'v2-write' | ok 0 "$BIN" set app/V2
ok 0 "$BIN" migrate; ok 0 "$BIN" get app/V2
ok 0 "$BIN" rekey
NEWKEY=$(grep -E '^[0-9a-f]{64}$' "$D/out"); export SEC_KEY="$NEWKEY"
ok 0 "$BIN" get app/TOKEN
ok 0 "$BIN" rm app2 --all; ok 0 "$BIN" rm app/GEN
echo "smoke: fails=$fails"
[ "$fails" = 0 ]
