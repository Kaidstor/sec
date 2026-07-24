package command

import (
	"github.com/kaidstor/sec/internal/audit"
	"github.com/kaidstor/sec/internal/store"

	"bytes"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/template"
)

// ---------------------------------------------------------------------------
// render: подстановка секретов в шаблоны конфигов не-env формата (yaml, json,
// toml, …). Синтаксис Go text/template: {{ secret "proj/KEY" }} или
// {{ secret "KEY" }} (проект — из --proj либо имени текущей папки).
// Результат — только в файл, как у export.
// ---------------------------------------------------------------------------

// lookupRef — как resolveRef, но возвращает ошибку вместо die (для шаблонов).
// env (инстанс) применяется и к коротким "KEY", и к полным "service/KEY".
func lookupRef(st *store.Store, defService, env, ref string) (string, error) {
	service, key, ok := strings.Cut(ref, "/")
	if !ok {
		service, key = defService, ref
	}
	proj := store.ProjKey(service, env)
	sec, _, _, found := st.Lookup(proj, key) // ссылки/наследование разрешаем как везде
	if !found {
		return "", fmt.Errorf("нет секрета %s/%s", proj, key)
	}
	if sec.IsBinary() {
		return "", fmt.Errorf("%s/%s — бинарный (файловый) секрет, в текстовый шаблон не подставляется (sec get --out)", proj, key)
	}
	return sec.Value, nil
}

func renderCommand(args []string) int {
	tpl, rest := splitArgs(args)
	fs := flag.NewFlagSet("render", flag.ExitOnError)
	var file, proj string
	fs.StringVar(&file, "file", "", "куда записать результат (обязателен)")
	fs.StringVar(&proj, "proj", "", "проект для коротких ссылок (умолч. — текущая папка)")
	getEnv := addEnvFlag(fs)
	_ = fs.Parse(rest)
	if tpl == "" {
		tpl = fs.Arg(0)
	}
	if tpl == "" {
		die("укажи шаблон: sec render config.tpl --file config.yml")
	}
	if file == "" {
		die("render пишет только в файл (защита от утечки в вывод): --file <out>")
	}
	if proj == "" {
		proj = cwdProject()
	}
	env := resolvedEnv(getEnv(), proj)
	checkEnv(env)

	data, err := os.ReadFile(tpl)
	if err != nil {
		die("чтение %s: %v", tpl, err)
	}
	st, _, _, err := store.Open(false)
	if err != nil {
		die("%v", err)
	}
	t, err := template.New(tpl).Funcs(template.FuncMap{
		"secret": func(ref string) (string, error) { return lookupRef(st, proj, env, ref) },
	}).Parse(string(data))
	if err != nil {
		die("шаблон %s: %v", tpl, err)
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, nil); err != nil {
		die("рендер: %v", err)
	}
	if err := writeSecretFile(file, buf.Bytes()); err != nil {
		die("запись %s: %v", file, err)
	}
	audit.Record("render", proj, tpl+" → "+file)
	fmt.Printf("записан %s (0600) из шаблона %s\n", file, tpl)
	return 0
}
