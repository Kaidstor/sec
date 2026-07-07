package store

import "strings"

// Адресация проектов с инстансом/окружением. Внутренний ключ стора склеивает
// сервис и инстанс через '@' (которого нет в проектных именах), поэтому сервисы
// без инстанса лежат как раньше, а бэкап/скан/мердж видят "service@env" как
// обычный проект. Пара ProjKey/BaseAndEnv — прямое и обратное преобразование.

// ProjKey — внутренний ключ проекта из сервиса и инстанса ("" — без инстанса).
func ProjKey(service, env string) string {
	if env == "" {
		return service
	}
	return service + "@" + env
}

// BaseAndEnv — обратная к ProjKey: разбирает внутренний ключ обратно на
// сервис и инстанс ("" если инстанса нет). Для показа в ls/diff/doctor.
func BaseAndEnv(storeKey string) (string, string) {
	if svc, env, ok := strings.Cut(storeKey, "@"); ok {
		return svc, env
	}
	return storeKey, ""
}
