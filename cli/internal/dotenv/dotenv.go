package dotenv

// dotenv: парсинг для import и форматирование для export. Диалект
// минимальный: комментарии, префикс export, одинарные (литеральные) и
// двойные (с \" \\ \n) кавычки. Значения с $ не экранируются — dotenv-парсеры
// читают их как есть, а вот `source .env` в bash подставит переменную.

import (
	"fmt"
	"regexp"
	"strings"
)

// keyRe — валидное имя env-переменной (оно же годится ключом sec).
var keyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func Parse(data string) (map[string]string, []string) {
	out := map[string]string{}
	var warns []string
	for i, raw := range strings.Split(data, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			warns = append(warns, fmt.Sprintf("строка %d: нет '=', пропущена", i+1))
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			q := v[0]
			v = v[1 : len(v)-1]
			if q == '"' {
				v = strings.NewReplacer(`\"`, `"`, `\n`, "\n", `\\`, `\`).Replace(v)
			}
		}
		if !keyRe.MatchString(k) {
			warns = append(warns, fmt.Sprintf("строка %d: %q не годится как имя env-переменной, пропущена", i+1, k))
			continue
		}
		out[k] = v
	}
	return out, warns
}

func Line(k, v string) string {
	if v != "" && !strings.ContainsAny(v, " \t\"'#\\\n`") {
		return k + "=" + v
	}
	esc := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(v)
	return k + `="` + esc + `"`
}
