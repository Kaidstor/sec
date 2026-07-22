package command

// Автодополнение для шелла. Две части:
//   sec completion zsh|bash|fish  — печатает скрипт дополнения для шелла;
//   sec __complete <слова...>     — скрытый бэкенд: по уже набранным словам
//                                   печатает кандидатов (по одному в строке).
// Скрипт дёргает __complete на каждый TAB. Печатаются ТОЛЬКО имена (подкоманды,
// проекты, ключи, инстансы, флаги) — значения секретов сюда не попадают.
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
	"rm", "run", "export", "import", "push", "check", "scan", "redact",
	"render", "stale", "doctor", "backup", "restore", "sync", "rekey",
	"log", "info", "completion", "version", "help",
}

// refCommandSet — команды, чей позиционный аргумент это ссылка proj/KEY.
var refCommandSet = map[string]bool{
	"set": true, "gen": true, "get": true, "verify": true, "history": true,
	"undo": true, "redo": true, "forget": true, "meta": true, "otp": true,
	"mv": true, "cp": true, "link": true, "unlink": true, "rm": true,
	"find": true, // шаблон поиска — тот же proj/KEY, дополняем как ссылку
}

// projCommandSet — команды, чей позиционный аргумент это проект целиком.
var projCommandSet = map[string]bool{
	"run": true, "export": true, "import": true, "push": true, "ls": true,
	"check": true, "diff": true, "stale": true, "extend": true,
}

// fileCommandSet — команды, чей позиционный аргумент это путь (дополняем файлами).
var fileCommandSet = map[string]bool{
	"scan": true, "redact": true, "render": true, "backup": true, "restore": true,
}

// completionFlags — флаги по подкомандам (подсказки для дополнения; держать
// примерно в синхроне с флагами команд — рассинхрон не критичен, лишь косметика).
var completionFlags = map[string][]string{
	"set":     {"--clipboard", "--clear", "--stdin", "--note", "--kind", "--override", "-e", "--env"},
	"gen":     {"--len", "--symbols", "--clip", "--note", "--kind", "-e", "--env"},
	"get":     {"--clip", "--peek", "--fingerprint", "--once", "--prev", "--clear-after", "-e", "--env"},
	"history": {"--json", "-e", "--env"},
	"undo":    {"-e", "--env"},
	"redo":    {"-e", "--env"},
	"forget":  {"-e", "--env"},
	"meta":    {"--note", "--kind", "--rotate-url", "--rotate-every", "--expires", "--json", "-e", "--env"},
	"stale":   {"--older-than", "--json"},
	"otp":     {"--clip", "-e", "--env"},
	"verify":  {"-e", "--env"},
	"diff":    {"-e", "--env"},
	"ls":      {"-l", "--json", "--filter", "-f", "-e", "--env"},
	"find":    {"-l", "--json", "-e", "--env"},
	"rm":      {"--all", "-e", "--env"},
	"mv":      {"--force", "-e", "--env"},
	"cp":      {"--force", "-e", "--env"},
	"link":    {"--parent-env", "-e", "--env"},
	"unlink":  {"--drop", "-e", "--env"},
	"extend":  {"--from", "--remove", "--parent-env", "-e", "--env"},
	"run":     {"--only", "-v", "-e", "--env"},
	"export":  {"--file", "-e", "--env"},
	"import":  {"--file", "--from-json", "--clipboard", "--from-infisical", "--infisical-env", "--path", "--projectId", "--token", "-e", "--env"},
	"push":    {"--to-infisical", "--infisical-env", "--path", "--only", "-e", "--env"},
	"check":   {"--file", "--all-envs", "-e", "--env"},
	"scan":    {"--staged", "--min", "--history"},
	"redact":  {"--min", "--history", "--mask", "--file"},
	"render":  {"--file", "--proj", "-e", "--env"},
	"backup":  {"--file"},
	"restore": {"--file", "--replace"},
	"sync":    {"--file"},
	"log":     {"-n", "--json"},
	"info":    {"--json"},
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

	// значение -e/--env — инстансы из стора
	if last := prior[len(prior)-1]; last == "-e" || last == "--env" {
		return matchPrefix(storeEnvs(st), cur)
	}

	// флаг
	if strings.HasPrefix(cur, "-") {
		return matchPrefix(completionFlags[sub], cur)
	}

	switch {
	case refCommandSet[sub]:
		return refCandidates(st, cur)
	case projCommandSet[sub]:
		return matchPrefix(storeProjectBases(st), cur)
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

// refCandidates дополняет ссылку proj/KEY: до слэша — имена проектов с "/",
// после — ключи проекта (базового и всех его инстансов, включая унаследованные).
func refCandidates(st *store.Store, cur string) []string {
	if st == nil {
		return nil
	}
	if i := strings.IndexByte(cur, '/'); i >= 0 {
		proj := cur[:i]
		keys := map[string]bool{}
		for p := range st.Projects {
			if svc, _ := store.BaseAndEnv(p); svc == proj {
				for k := range st.EffectiveKeys(p) {
					keys[k] = true
				}
			}
		}
		out := make([]string, 0, len(keys))
		for k := range keys {
			out = append(out, proj+"/"+k)
		}
		return matchPrefix(out, cur)
	}
	bases := storeProjectBases(st)
	out := make([]string, 0, len(bases))
	for _, svc := range bases {
		out = append(out, svc+"/")
	}
	return matchPrefix(out, cur)
}

// storeProjectBases — уникальные имена сервисов (без инстанса) из стора.
func storeProjectBases(st *store.Store) []string {
	if st == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for p := range st.Projects {
		if svc, _ := store.BaseAndEnv(p); !seen[svc] {
			seen[svc] = true
			out = append(out, svc)
		}
	}
	return out
}

// storeEnvs — уникальные имена инстансов (часть после @) из стора.
func storeEnvs(st *store.Store) []string {
	if st == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for p := range st.Projects {
		if _, env := store.BaseAndEnv(p); env != "" && !seen[env] {
			seen[env] = true
			out = append(out, env)
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
