package command

// Автодополнение для шелла. Две части:
//   sec completion zsh|bash|fish  — печатает скрипт дополнения для шелла;
//   sec __complete <слова...>     — скрытый бэкенд: по уже набранным словам
//                                   печатает кандидатов (по одному в строке).
// Скрипт дёргает __complete на каждый TAB. Печатаются ТОЛЬКО имена (подкоманды,
// проекты, ключи, профили, флаги) — значения секретов сюда не попадают.
// Спецстрока "__files__" просит шелл дополнить путями (для scan/redact/backup/…).

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/kaidstor/sec/internal/store"
)

// completionSubcommands — подкоманды, предлагаемые первым словом (без скрытых
// __complete/__clearclip и без алиасов — только канонические имена).
var completionSubcommands = []string{
	"set", "gen", "get", "verify", "history", "undo", "redo", "forget",
	"meta", "otp", "ls", "find", "diff", "mv", "cp", "link", "unlink", "extend",
	"rm", "run", "export", "deploy", "import", "push", "check", "scan", "redact",
	"render", "share", "stale", "doctor", "backup", "restore", "sync", "rekey",
	"log", "info", "stats", "skills", "completion", "version", "help",
}

// knownCommands — те же имена множеством: счётчик использования (recordUsage)
// отмечает только их, чтобы в файл не попадали опечатки и скрытые __-команды.
var knownCommands = func() map[string]bool {
	m := make(map[string]bool, len(completionSubcommands))
	for _, c := range completionSubcommands {
		m[c] = true
	}
	return m
}()

// refCommandSet — команды, чей позиционный аргумент это ссылка proj/KEY.
var refCommandSet = map[string]bool{
	"set": true, "gen": true, "get": true, "verify": true, "history": true,
	"undo": true, "redo": true, "forget": true, "meta": true, "otp": true,
	"mv": true, "cp": true, "link": true, "unlink": true, "rm": true,
	"find": true, // шаблон поиска — тот же proj/KEY, дополняем как ссылку
}

// projCommandSet — команды, чей позиционный аргумент это проект целиком.
var projCommandSet = map[string]bool{
	"run": true, "export": true, "deploy": true, "import": true, "push": true,
	"ls": true, "check": true, "diff": true, "stale": true, "extend": true,
}

// fileCommandSet — команды, чей позиционный аргумент это путь (дополняем файлами).
var fileCommandSet = map[string]bool{
	"scan": true, "redact": true, "render": true, "backup": true, "restore": true,
}

// completionFlags — флаги по подкомандам (подсказки для дополнения; держать
// примерно в синхроне с флагами команд — рассинхрон не критичен, лишь косметика).
var completionFlags = map[string][]string{
	"skills":  {"--target", "--dir", "--link", "--force"},
	"set":     {"--clipboard", "--clear", "--stdin", "--from-file", "--note", "--kind", "--override"},
	"gen":     {"--len", "--symbols", "--clip", "--note", "--kind"},
	"get":     {"--clip", "--peek", "--fingerprint", "--once", "--prev", "--clear-after", "--out"},
	"history": {"--json"},
	"meta":    {"--note", "--kind", "--rotate-url", "--rotate-every", "--expires", "--json"},
	"stale":   {"--older-than", "--json"},
	"otp":     {"--clip"},
	"diff":    {"--sudo", "--only"},
	"ls":      {"-l", "--json", "--filter", "-f"},
	"find":    {"-l", "--json"},
	"rm":      {"--all"},
	"mv":      {"--force"},
	"cp":      {"--force"},
	"unlink":  {"--drop"},
	"extend":  {"--from", "--remove"},
	"run":     {"--only", "--file", "--include-files", "-v"},
	"export":  {"--file", "--include-files"},
	"link":    {"--force"},
	"deploy":  {"--to", "--only", "--after", "--sudo", "--replace", "--no-backup", "--dry-run", "--yes"},
	"import":  {"--file", "--from-json", "--clipboard", "--from-infisical", "--infisical-env", "--path", "--projectId", "--token"},
	"push":    {"--to-infisical", "--infisical-env", "--path", "--only"},
	"check":   {"--file", "--all-profiles"},
	"scan":    {"--staged", "--min", "--history", "--include-config"},
	"redact":  {"--min", "--history", "--include-config", "--mask", "--file"},
	"render":  {"--file", "--proj"},
	"share":   {"--ttl", "--multi", "--file", "--no-clip"},
	"backup":  {"--file"},
	"restore": {"--file", "--replace"},
	"sync":    {"--file"},
	"log":     {"-n", "--all", "--json"},
	"info":    {"--json"},
	"stats":   {"--days", "--all", "--json"},
}

// completionCommand печатает скрипт дополнения для указанного шелла.
func completionCommand(args []string) int {
	shell := ""
	if len(args) > 0 {
		shell = args[0]
	}
	var script string
	switch shell {
	case "zsh":
		script = zshCompletion
	case "bash":
		script = bashCompletion
	case "fish":
		script = fishCompletion
	default:
		die("укажи шелл: sec completion zsh|bash|fish")
	}
	os.Stdout.WriteString(script)
	return 0
}

// completeCommand — скрытый бэкенд (sec __complete <слова...>): открывает стор
// best-effort и печатает кандидатов. Ошибки молчаливые (без стора дополняем
// подкоманды/флаги; значения секретов не печатаются никогда).
func completeCommand(args []string) int {
	st, _, _, err := store.Open(false)
	if err != nil {
		st = nil
	}
	for _, c := range completeCandidates(st, args) {
		fmt.Println(c)
	}
	return 0
}

// completeCandidates — чистая логика дополнения (тестируется без диска). args —
// слова после `sec`, последнее это дополняемое слово (может быть пустым).
func completeCandidates(st *store.Store, args []string) []string {
	cur := ""
	if len(args) > 0 {
		cur = args[len(args)-1]
	}
	var prior []string
	if len(args) > 1 {
		prior = args[:len(args)-1]
	}

	// первое слово — сама подкоманда
	if len(prior) == 0 {
		return matchPrefix(completionSubcommands, cur)
	}
	sub := canonicalSub(prior[0])

	// флаг
	if strings.HasPrefix(cur, "-") {
		return matchPrefix(completionFlags[sub], cur)
	}

	// первый аргумент share смешанный: сабкоманды и ссылка proj/KEY —
	// поэтому share не входит в refCommandSet
	if sub == "share" && len(prior) == 1 {
		return matchPrefix(append([]string{"setup", "ls", "revoke"}, refCandidates(st, cur)...), cur)
	}

	switch {
	case refCommandSet[sub]:
		return refCandidates(st, cur)
	case projCommandSet[sub]:
		return matchPrefix(storeProjectNames(st), cur)
	case fileCommandSet[sub]:
		return []string{"__files__"}
	}
	return nil
}

// canonicalSub сводит алиасы к каноническому имени команды.
func canonicalSub(s string) string {
	switch s {
	case "generate":
		return "gen"
	case "list":
		return "ls"
	case "search":
		return "find"
	case "move":
		return "mv"
	case "copy":
		return "cp"
	}
	return s
}

// refCandidates дополняет ссылку proj[@profile]/KEY: до слэша — имена
// проектов (базовые и с профилем) с "/", после — ключи проекта. Для базового
// имени без '@' ключи собираются по всем профилям сервиса (включая
// унаследованные), для явного @-адреса — только его.
func refCandidates(st *store.Store, cur string) []string {
	if st == nil {
		return nil
	}
	if i := strings.IndexByte(cur, '/'); i >= 0 {
		projPart := cur[:i]
		base, prof, explicit := splitProfile(projPart)
		keys := map[string]bool{}
		if explicit {
			for k := range st.EffectiveKeys(store.ProjKey(base, prof)) {
				keys[k] = true
			}
		} else {
			for p := range st.Projects {
				if svc, _ := store.BaseAndProfile(p); svc == projPart {
					for k := range st.EffectiveKeys(p) {
						keys[k] = true
					}
				}
			}
		}
		out := make([]string, 0, len(keys))
		for k := range keys {
			out = append(out, projPart+"/"+k)
		}
		return matchPrefix(out, cur)
	}
	names := storeProjectNames(st)
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, n+"/")
	}
	return matchPrefix(out, cur)
}

// storeProjectNames — имена проектов для дополнения: базовые сервисы плюс
// полные формы с профилем (svc@prod).
func storeProjectNames(st *store.Store) []string {
	if st == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for p := range st.Projects {
		svc, _ := store.BaseAndProfile(p)
		for _, n := range []string{svc, p} {
			if !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	return out
}

// matchPrefix — отфильтровать по префиксу, убрать дубли, отсортировать.
func matchPrefix(cands []string, prefix string) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range cands {
		if c != "" && strings.HasPrefix(c, prefix) && !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	sort.Strings(out)
	return out
}

// --- скрипты дополнения (дёргают `sec __complete` на каждый TAB) ---

const zshCompletion = `#compdef sec
# Автодополнение sec для zsh. Работает двумя способами:
#   - eval "$(sec completion zsh)"  в ~/.zshrc (после compinit);
#   - как автозагружаемый файл _sec в fpath (его ставит brew).
compdef _sec sec 2>/dev/null

_sec() {
  local -a raw slash noslash
  raw=("${(@f)$(sec __complete "${(@)words[2,CURRENT]}" 2>/dev/null)}")
  if (( ${raw[(I)__files__]} )); then
    _files
    return
  fi
  local c
  for c in $raw; do
    [[ -n "$c" ]] || continue
    if [[ "$c" == */ ]]; then slash+=("$c"); else noslash+=("$c"); fi
  done
  (( $#slash ))   && compadd -S '' -- $slash
  (( $#noslash )) && compadd -- $noslash
}

# Автозагрузка из fpath: zsh запускает файл как функцию _sec — сразу дополняем.
if [ "${funcstack[1]}" = "_sec" ]; then
  _sec "$@"
fi
`

const bashCompletion = `# Автодополнение sec для bash. Установка (в ~/.bashrc):
#   eval "$(sec completion bash)"
_sec() {
  local cur candidates IFS=$'\n'
  cur="${COMP_WORDS[COMP_CWORD]}"
  candidates=( $(sec __complete "${COMP_WORDS[@]:1:COMP_CWORD}" 2>/dev/null) )
  if [[ " ${candidates[*]} " == *" __files__ "* ]]; then
    COMPREPLY=( $(compgen -f -- "$cur") )
    return
  fi
  COMPREPLY=( $(compgen -W "${candidates[*]}" -- "$cur") )
  if [[ ${#COMPREPLY[@]} -gt 0 && "${COMPREPLY[0]}" == */ ]]; then
    compopt -o nospace 2>/dev/null
  fi
}
complete -F _sec sec
`

const fishCompletion = `# Автодополнение sec для fish. Установка:
#   sec completion fish > ~/.config/fish/completions/sec.fish
function __sec_complete
    set -l tokens (commandline -opc) (commandline -ct)
    set -l out (sec __complete $tokens[2..-1] 2>/dev/null)
    if test "$out" = "__files__"
        __fish_complete_path (commandline -ct)
    else
        printf '%s\n' $out
    end
end
complete -c sec -f -a '(__sec_complete)'
`
