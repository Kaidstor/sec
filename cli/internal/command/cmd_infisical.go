package command

// Связка команд с Infisical: import --from-infisical (Infisical → локальный
// стор) и push --to-infisical (стор → Infisical). Работа с CLI и перенос
// значений вынесены в пакет internal/infisical; здесь только маппинг на стор.
//
// Адресация: sec-проект <proj> ↔ набор секретов в Infisical (env/path/project).
// Без --projectId проект берётся из окружающего .infisical.json (как это делает
// `infisical run/export` в папке сервиса).

import (
	"github.com/kaidstor/sec/internal/audit"
	"github.com/kaidstor/sec/internal/store"

	"flag"
	"fmt"
	"strings"

	"github.com/kaidstor/sec/internal/infisical"
)

func importFromInfisical(proj, env, path, projectID, token string) int {
	kv, err := infisical.Pull(infisical.Ref{Env: env, Path: path, ProjectID: projectID, Token: token})
	if err != nil {
		die("%v", err)
	}
	if len(kv) == 0 {
		die("Infisical (env=%s path=%s) не вернул ни одного секрета", env, path)
	}
	writeImported(proj, kv, fmt.Sprintf("из Infisical env=%s path=%s", env, path))
	return 0
}

func pushCommand(args []string) int {
	service, rest := splitArgs(args)
	fs := flag.NewFlagSet("push", flag.ExitOnError)
	var toInfisical bool
	var ienv, path, projectID, token, only string
	fs.BoolVar(&toInfisical, "to-infisical", false, "цель — Infisical (через их CLI)")
	fs.StringVar(&ienv, "infisical-env", "", "Infisical: окружение (умолч. — значение -e, иначе dev)")
	fs.StringVar(&path, "path", "/", "Infisical: путь к папке секретов")
	fs.StringVar(&projectID, "projectId", "", "Infisical: id проекта (иначе из .infisical.json в текущей папке)")
	fs.StringVar(&token, "token", "", "Infisical: сервис-токен/идентификатор (иначе текущий логин)")
	fs.StringVar(&only, "only", "", "отправить только эти ключи (через запятую)")
	getEnv := addEnvFlag(fs)
	_ = fs.Parse(rest)
	if !toInfisical {
		die("укажи цель: sec push <proj> --to-infisical [-e commercial --infisical-env prod]")
	}
	sp, secEnv := resolveServiceProj(service, fs, getEnv())
	if ienv == "" {
		if ienv = secEnv; ienv == "" {
			ienv = "dev"
		}
	}

	st, _, _, err := store.Open(false)
	if err != nil {
		die("%v", err)
	}
	keys := st.EffectiveKeys(sp) // собственные + унаследованные, ссылки разрешены
	if len(keys) == 0 {
		die("проект %q пуст или не существует (sec ls)", sp)
	}

	kv := selectKeys(keys, only, sp)

	if err := infisical.Push(infisical.Ref{Env: ienv, Path: path, ProjectID: projectID, Token: token}, kv); err != nil {
		die("%v", err)
	}
	audit.Record("push", sp, fmt.Sprintf("→ Infisical env=%s path=%s (%d ключей)", ienv, path, len(kv)))
	fmt.Printf("отправлено из %s в Infisical (env=%s path=%s): %s\n", sp, ienv, path, strings.Join(store.SortedKeys(kv), ", "))
	return 0
}
