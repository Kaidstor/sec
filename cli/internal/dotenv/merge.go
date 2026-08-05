package dotenv

// Merge — точечная правка существующего .env вместо пересборки файла целиком.
// Нужна для sec deploy: прод-конфиг живёт своей жизнью (комментарии, порядок,
// ключи, которых в сторе нет), и переписанный целиком файл потом не сверить с
// прежним ни глазами, ни diff'ом.

import (
	"sort"
	"strings"
)

// Merge вписывает значения kv в текст .env, сохраняя порядок строк, комментарии,
// пустые строки, отступ и префикс export. Ключи, которых в тексте нет,
// дописываются в конец. Строки ключей, отсутствующих в kv, не трогаются вовсе —
// поэтому в kv передавать только то, что реально надо изменить, иначе совпадающие
// значения перепишутся в каноническую форму и дадут шум в diff.
//
// Ключ, встреченный в файле несколько раз, переписывается везде: dotenv-парсеры
// берут последнее вхождение, но оставленное прежнее значение выше по файлу
// сбивает с толку при чтении глазами.
func Merge(orig string, kv map[string]string) (out string, updated, added []string) {
	const bomRune = "\ufeff"
	bom := ""
	if strings.HasPrefix(orig, bomRune) { // BOM от редакторов Windows — сохраняем как есть
		bom, orig = bomRune, strings.TrimPrefix(orig, bomRune)
	}

	var lines []string
	endsWithNL := false
	if orig != "" {
		lines = strings.Split(orig, "\n")
		if last := len(lines) - 1; lines[last] == "" {
			lines, endsWithNL = lines[:last], true
		}
	}

	seen := map[string]bool{}
	for i, raw := range lines {
		body, cr := raw, ""
		if strings.HasSuffix(body, "\r") { // CRLF-файл: терминатор строки сохраняем
			body, cr = body[:len(body)-1], "\r"
		}
		k, ok := lineKey(body)
		if !ok {
			continue
		}
		v, want := kv[k]
		if !want {
			continue
		}
		lines[i] = rewriteLine(body, k, v) + cr
		if !seen[k] {
			seen[k] = true
			updated = append(updated, k)
		}
	}

	fresh := make([]string, 0, len(kv))
	for k := range kv {
		if !seen[k] {
			fresh = append(fresh, k)
		}
	}
	sort.Strings(fresh)
	// Дописанные строки получают терминатор файла, а не свой: смешанный
	// CRLF/LF ломает часть парсеров и даёт мусорный diff в редакторе.
	cr := ""
	if strings.Contains(orig, "\r\n") {
		cr = "\r"
	}
	for _, k := range fresh {
		lines = append(lines, Line(k, kv[k])+cr)
	}

	out = bom + strings.Join(lines, "\n")
	if len(lines) > 0 && (endsWithNL || len(fresh) > 0) {
		out += "\n"
	}
	return out, updated, fresh
}

// MultilineKeys — ключи, чьё значение открывает кавычку и не закрывает её в той
// же строке. Диалект многострочных значений не поддерживает (см. шапку
// dotenv.go), поэтому построчный Merge разорвал бы такое значение пополам:
// первую строку заменил бы канонической формой, а хвост оставил висеть в файле.
// Merge этого не заметит, Parse — тоже, так что ловить приходится отдельно.
func MultilineKeys(data string) []string {
	var out []string
	for _, raw := range strings.Split(strings.TrimPrefix(data, "\ufeff"), "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, ok := lineKey(line)
		if !ok {
			continue
		}
		_, v, _ := strings.Cut(strings.TrimPrefix(line, "export "), "=")
		v = strings.TrimSpace(v)
		if len(v) > 0 && (v[0] == '"' || v[0] == '\'') && !(len(v) >= 2 && v[len(v)-1] == v[0]) {
			out = append(out, k)
		}
	}
	return out
}

// lineKey достаёт имя ключа из строки .env по тем же правилам, что и Parse
// (комментарии, префикс export, пробелы вокруг имени). ok=false — строка не пара
// KEY=VALUE. Держать в синхроне с Parse: разошедшиеся правила означают, что
// deploy перепишет не ту строку, которую видит diff.
func lineKey(raw string) (string, bool) {
	line := strings.TrimSpace(raw)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", false
	}
	line = strings.TrimPrefix(line, "export ")
	k, _, ok := strings.Cut(line, "=")
	if !ok {
		return "", false
	}
	k = strings.TrimSpace(k)
	if !keyRe.MatchString(k) {
		return "", false
	}
	return k, true
}

// rewriteLine собирает новую строку на месте старой, сохраняя её отступ и
// префикс export (значение форматирует Line — с кавычками там, где нужно).
func rewriteLine(raw, key, val string) string {
	indent := raw[:len(raw)-len(strings.TrimLeft(raw, " \t"))]
	prefix := ""
	if strings.HasPrefix(strings.TrimSpace(raw), "export ") {
		prefix = "export "
	}
	return indent + prefix + Line(key, val)
}
