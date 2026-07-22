package dotenv

// dotenv: парсинг для import и форматирование для export. Диалект
// минимальный: комментарии, префикс export, одинарные (литеральные) и
// двойные (с \" \\ \n \r) кавычки. Значения с $ не экранируются — dotenv-парсеры
// читают их как есть, а вот `source .env` в bash подставит переменную.
//
// Инлайн-комментарии не поддерживаются намеренно: `KEY=abc # хвост` — это
// значение целиком, иначе секрет с решёткой молча обрежется.

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
	data = strings.TrimPrefix(data, "\ufeff") // BOM от редакторов Windows — иначе первый ключ битый
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
				v = strings.NewReplacer(`\"`, `"`, `\n`, "\n", `\r`, "\r", `\\`, `\`).Replace(v)
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

// Line форматирует пару для .env. Кавычки ставятся, если значение пустое,
// содержит спецсимвол или обрамлено пробельным — иначе Parse обрежет края
// (TrimSpace) и значение вернётся искажённым.
func Line(k, v string) string {
	if v != "" && v == strings.TrimSpace(v) && !strings.ContainsAny(v, " \t\"'#\\\n\r`") {
		return k + "=" + v
	}
	esc := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`).Replace(v)
	return k + `="` + esc + `"`
}
