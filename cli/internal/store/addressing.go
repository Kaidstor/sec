package store

import "strings"

// Адресация проектов с профилем. Внутренний ключ стора склеивает сервис и
// профиль через '@' (которого нет в проектных именах) — та же форма, что и в
// CLI-адресе (service@profile/KEY), поэтому проекты без профиля лежат как
// раньше, а бэкап/скан/мердж видят "service@profile" как обычный проект.
// Пара ProjKey/BaseAndProfile — прямое и обратное преобразование.

// ProjKey — внутренний ключ проекта из сервиса и профиля ("" — без профиля).
func ProjKey(service, profile string) string {
	if profile == "" {
		return service
	}
	return service + "@" + profile
}

// BaseAndProfile — обратная к ProjKey: разбирает внутренний ключ обратно на
// сервис и профиль ("" если профиля нет). Для показа в ls/diff/doctor.
func BaseAndProfile(storeKey string) (string, string) {
	if svc, profile, ok := strings.Cut(storeKey, "@"); ok {
		return svc, profile
	}
	return storeKey, ""
}
