package command

// Фильтрация имён для `sec ls --filter` и `sec find`: подстрока без учёта
// регистра либо glob (* и ?), если в шаблоне есть подстановочные символы.
// Фильтр работает только по именам (проекты, инстансы, ключи) — значений
// секретов он не видит и в вывод их не приносит.

import "strings"

// matchFilter — подходит ли name под шаблон pat. Пустой шаблон подходит всему
// (удобно как «фильтр не задан»).
func matchFilter(pat, name string) bool {
	if pat == "" {
		return true
	}
	p, n := strings.ToLower(pat), strings.ToLower(name)
	if strings.ContainsAny(p, "*?") {
		return globMatch(p, n)
	}
	return strings.Contains(n, p)
}

// globMatch — сопоставление с шаблоном: * это любая последовательность (в том
// числе пустая), ? — ровно один символ. В отличие от path.Match разделителей не
// знает: имена проектов и ключей плоские. Итеративный алгоритм с откатом на
// последнюю звёздочку (без рекурсии).
func globMatch(pat, s string) bool {
	p, r := []rune(pat), []rune(s)
	pi, si, star, mark := 0, 0, -1, 0
	for si < len(r) {
		switch {
		case pi < len(p) && (p[pi] == '?' || p[pi] == r[si]):
			pi++
			si++
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, si
			pi++
		case star >= 0: // не сошлось — вернуться к звёздочке, отдав ей ещё символ
			pi = star + 1
			mark++
			si = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}
