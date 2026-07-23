package command

// Команды над проектом/стором целиком: ls / find / run / export / import /
// log / info.

import (
	"github.com/kaidstor/sec/internal/audit"
	"github.com/kaidstor/sec/internal/dotenv"
	"github.com/kaidstor/sec/internal/keyring"
	"github.com/kaidstor/sec/internal/store"

	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

func lsCommand(args []string) int {
	service, rest := splitArgs(args)
	fs := flag.NewFlagSet("ls", flag.ExitOnError)
	var long, asJSON bool
	var filter string
	fs.BoolVar(&long, "l", false, "показать даты обновления / метаданные")
	fs.BoolVar(&asJSON, "json", false, "машинный вывод JSON (без значений)")
	fs.StringVar(&filter, "filter", "", "показать только совпавшие имена: подстрока без учёта регистра или glob (*_TOKEN)")
	fs.StringVar(&filter, "f", "", "то же, что --filter (короткая форма)")
	getEnv := addEnvFlag(fs)
	_ = fs.Parse(rest)
	if service == "" {
		service = fs.Arg(0)
	}
	env := getEnv()
	checkEnv(env)

	st, mkey, _, err := store.Open(false)
	if err != nil {
		die("%v", err)
	}

	// инстансы сервиса (env-части ключей вида service@env), отсортированные
	instancesOf := func(svc string) []string {
		set := map[string]struct{}{}
		for p := range st.Projects {
			if b, e := store.BaseAndEnv(p); b == svc && e != "" {
				set[e] = struct{}{}
			}
		}
		return store.SortedKeys(set)
	}

	// --filter отсекает имена того, что сейчас показываем: проекты, инстансы
	// или ключи. Поиск по всему стору разом — отдельная команда sec find.
	keep := func(name string) bool { return matchFilter(filter, name) }
	nothingFound := func() int {
		fmt.Printf("ничего не найдено по фильтру %q (искать по всему хранилищу: sec find '%s')\n", filter, filter)
		return 0
	}

	if asJSON {
		type keyInfo struct {
			Key         string      `json:"key"`
			Ref         string      `json:"ref,omitempty"` // CLI-адрес родителя, если ключ — ссылка
			Enc         string      `json:"enc,omitempty"` // "b64" — бинарный (файловый) секрет
			UpdatedAt   string      `json:"updatedAt"`
			History     int         `json:"history"`
			Chars       int         `json:"chars"`
			Fingerprint string      `json:"fingerprint"`
			Meta        *store.Meta `json:"meta,omitempty"`
		}
		// keyFilter пуст в списке проектов (там фильтруются их имена) и равен
		// --filter, когда показываем ключи конкретного проекта.
		build := func(proj, keyFilter string) []keyInfo {
			own := st.Projects[proj]
			out := []keyInfo{}
			for _, k := range store.SortedKeys(own) {
				if !matchFilter(keyFilter, k) {
					continue
				}
				s := own[k]
				info := keyInfo{Key: k, Enc: s.Enc, UpdatedAt: s.UpdatedAt, History: len(s.History), Meta: s.Meta}
				val := s.Value
				if s.Ref != "" { // ссылка — отпечаток/длина считаем по значению родителя
					info.Ref = store.RefToCLI(s.Ref)
					if r, _, ok := st.ResolveSecret(proj, k); ok {
						val = r.Value
					} else {
						val = ""
					}
				}
				info.Chars = len([]rune(val))
				info.Fingerprint = store.Fingerprint(mkey, val)
				out = append(out, info)
			}
			return out
		}
		var v any
		switch {
		case service == "":
			m := map[string][]keyInfo{}
			for p := range st.Projects {
				base, _ := store.BaseAndEnv(p)
				if !keep(base) {
					continue
				}
				m[p] = build(p, "")
			}
			v = m
		case env == "" && len(instancesOf(service)) > 0:
			m := map[string][]keyInfo{}
			for _, e := range instancesOf(service) {
				if !keep(e) {
					continue
				}
				m[e] = build(store.ProjKey(service, e), "")
			}
			v = m
		default:
			v = build(store.ProjKey(service, env), filter)
		}
		data, _ := json.MarshalIndent(v, "", "  ")
		fmt.Println(string(data))
		return 0
	}

	// список сервисов: группируем service@env под базовым сервисом
	if service == "" {
		if len(st.Projects) == 0 {
			fmt.Println("хранилище пусто")
			return 0
		}
		bases := map[string]struct{}{}
		for p := range st.Projects {
			b, _ := store.BaseAndEnv(p)
			bases[b] = struct{}{}
		}
		shown := 0
		for _, b := range store.SortedKeys(bases) {
			if !keep(b) {
				continue
			}
			shown++
			if insts := instancesOf(b); len(insts) > 0 {
				fmt.Printf("%-24s инстансы: %s\n", b, strings.Join(insts, ", "))
			} else {
				fmt.Printf("%-24s %d ключ(ей)\n", b, len(st.Projects[b]))
			}
		}
		if shown == 0 {
			return nothingFound()
		}
		return 0
	}

	// сервис без -e и с инстансами → показать инстансы
	if env == "" {
		if insts := instancesOf(service); len(insts) > 0 {
			shown := 0
			for _, e := range insts {
				if !keep(e) {
					continue
				}
				shown++
				fmt.Printf("%-18s -e %-14s %d ключ(ей)\n", service, e, len(st.Projects[store.ProjKey(service, e)]))
			}
			if shown == 0 {
				return nothingFound()
			}
			return 0
		}
	}

	// ключи конкретного проекта (service или service@env), включая унаследованные
	sp := store.ProjKey(service, env)
	eff := st.EffectiveKeys(sp)
	if len(eff) == 0 {
		die("проект %q пуст или не существует (sec ls)", sp)
	}
	if parents := st.Extends[sp]; len(parents) > 0 {
		var labels []string
		for _, p := range parents {
			if svc, penv := store.BaseAndEnv(p); penv == "" {
				labels = append(labels, svc)
			} else {
				labels = append(labels, svc+" -e "+penv)
			}
		}
		fmt.Printf("наследует (read-only): %s\n", strings.Join(labels, ", "))
	}
	shown := 0
	for _, k := range store.SortedKeys(eff) {
		if !keep(k) {
			continue
		}
		shown++
		_, org, source, _ := st.Lookup(sp, k)
		mark := ""
		switch org {
		case store.OriginRef:
			mark = "  → " + store.RefToCLI(source)
		case store.OriginExtend:
			mark = "  ⤷ " + store.RefToCLI(source)
		}
		if long {
			fmt.Printf("%-32s %s%s\n", k, keyDetails(eff[k]), mark)
		} else {
			fmt.Println(k + mark)
		}
	}
	if shown == 0 {
		return nothingFound()
	}
	return 0
}

// findCommand ищет ключи по всему хранилищу и печатает адреса совпавших
// (значений не показывает) — чтобы не листать стор целиком в поисках нужного.
// Шаблон: подстрока без учёта регистра либо glob (* и ?); со слэшем внутри
// («gidcaf/*TOKEN») левая часть матчится на проект, правая — на ключ.
func findCommand(args []string) int {
	pat, rest := splitArgs(args)
	fs := flag.NewFlagSet("find", flag.ExitOnError)
	var long, asJSON bool
	fs.BoolVar(&long, "l", false, "показать даты обновления / метаданные")
	fs.BoolVar(&asJSON, "json", false, "машинный вывод JSON (без значений)")
	getEnv := addEnvFlag(fs)
	_ = fs.Parse(rest)
	if pat == "" {
		pat = fs.Arg(0)
	}
	if pat == "" {
		die("укажи, что искать: sec find <шаблон> (подстрока или glob, напр. token, '*_URL', 'gidcaf/*')")
	}
	env := getEnv()
	checkEnv(env)
	projPat, keyPat, scoped := strings.Cut(pat, "/")

	st, _, _, err := store.Open(false)
	if err != nil {
		die("%v", err)
	}

	type hit struct {
		Ref       string      `json:"ref"`     // CLI-адрес: svc/KEY (+ " -e инстанс")
		Project   string      `json:"project"` // сервис без инстанса
		Env       string      `json:"env,omitempty"`
		Key       string      `json:"key"`
		Link      string      `json:"link,omitempty"` // куда указывает ключ-ссылка
		UpdatedAt string      `json:"updatedAt"`
		History   int         `json:"history"`
		Meta      *store.Meta `json:"meta,omitempty"`
	}
	hits := []hit{}
	for _, p := range store.SortedKeys(st.Projects) {
		base, penv := store.BaseAndEnv(p)
		if env != "" && penv != env {
			continue
		}
		projHit := matchFilter(projPat, base)
		if scoped && !projHit {
			continue
		}
		for _, k := range store.SortedKeys(st.Projects[p]) {
			switch {
			case scoped: // «проект/ключ» — ключ обязан совпасть со своей частью
				if !matchFilter(keyPat, k) {
					continue
				}
			case !projHit && !matchFilter(pat, k): // иначе хватает совпадения проекта или ключа
				continue
			}
			s := st.Projects[p][k]
			h := hit{Ref: store.RefToCLI(p + "/" + k), Project: base, Env: penv, Key: k,
				UpdatedAt: s.UpdatedAt, History: len(s.History), Meta: s.Meta}
			if s.Ref != "" {
				h.Link = store.RefToCLI(s.Ref)
			}
			hits = append(hits, h)
		}
	}

	if len(hits) == 0 {
		if asJSON {
			fmt.Println("[]")
		} else {
			fmt.Fprintf(os.Stderr, "sec: по %q ничего не нашлось (sec ls — весь список проектов)\n", pat)
		}
		return 1 // как у grep: пусто — ненулевой код, удобно как условие в скрипте
	}
	if asJSON {
		data, _ := json.MarshalIndent(hits, "", "  ")
		fmt.Println(string(data))
		return 0
	}
	for _, h := range hits {
		mark := ""
		if h.Link != "" {
			mark = "  → " + h.Link
		}
		if long {
			s := st.Projects[store.ProjKey(h.Project, h.Env)][h.Key]
			fmt.Printf("%-40s %s%s\n", h.Ref, keyDetails(s), mark)
		} else {
			fmt.Println(h.Ref + mark)
		}
	}
	return 0
}

// runCommand запускает команду, подменив себя ею (exec) с env-инъекцией
// секретов проекта — значения живут только в окружении дочернего процесса.
func runCommand(args []string) int {
	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i
			break
		}
	}
	if sep < 0 {
		die("нужен разделитель --: sec run [proj] [--only A,B] -- cmd args...")
	}
	head, tail := args[:sep], args[sep+1:]
	if len(tail) == 0 {
		die("нет команды после --")
	}

	service, rest := splitArgs(head)
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	var only string
	var verbose bool
	fs.StringVar(&only, "only", "", "инъектить только перечисленные ключи (через запятую)")
	fs.BoolVar(&verbose, "v", false, "показать имена инъектированных ключей")
	getEnv := addEnvFlag(fs)
	_ = fs.Parse(rest)
	proj, _ := resolveServiceProj(service, fs, getEnv())

	st, _, _, err := store.Open(false)
	if err != nil {
		die("%v", err)
	}
	keys := st.EffectiveKeys(proj) // собственные + унаследованные, ссылки разрешены
	if len(keys) == 0 {
		die("проект %q пуст или не существует (sec ls)", proj)
	}

	extra := selectKeys(keys, only, proj)
	if verbose {
		fmt.Fprintf(os.Stderr, "[%s → env += %s]\n", proj, strings.Join(store.SortedKeys(extra), ", "))
	}

	path, err := exec.LookPath(tail[0])
	if err != nil {
		die("команда не найдена: %s", tail[0])
	}
	audit.Record("run", proj, fmt.Sprintf("env += %s → %s", strings.Join(store.SortedKeys(extra), ","), tail[0]))
	code, err := execReplace(path, tail, mergedEnv(extra))
	if err != nil {
		die("exec %s: %v", tail[0], err)
	}
	return code // на unix недостижимо: exec замещает процесс (см. exec_<os>.go)
}

// mergedEnv накладывает extra поверх текущего окружения без дублей
// (при дублях в envp что подхватится — не определено).
func mergedEnv(extra map[string]string) []string {
	seen := map[string]int{}
	var out []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if idx, ok := seen[k]; ok {
			out[idx] = kv
		} else {
			seen[k] = len(out)
			out = append(out, kv)
		}
	}
	for _, k := range store.SortedKeys(extra) {
		kv := k + "=" + extra[k]
		if idx, ok := seen[k]; ok {
			out[idx] = kv
		} else {
			seen[k] = len(out)
			out = append(out, kv)
		}
	}
	return out
}

func exportCommand(args []string) int {
	service, rest := splitArgs(args)
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	var file string
	fs.StringVar(&file, "file", "", "путь к .env-файлу (обязателен)")
	getEnv := addEnvFlag(fs)
	_ = fs.Parse(rest)
	proj, _ := resolveServiceProj(service, fs, getEnv())
	if file == "" {
		die("export пишет только в файл (защита от утечки в вывод): sec export %s --file .env", proj)
	}

	st, _, _, err := store.Open(false)
	if err != nil {
		die("%v", err)
	}
	keys := st.EffectiveKeys(proj) // собственные + унаследованные, ссылки разрешены
	if len(keys) == 0 {
		die("проект %q пуст или не существует (sec ls)", proj)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# сгенерировано sec из проекта %s — не коммитить\n", proj)
	var written, binSkipped []string
	for _, k := range store.SortedKeys(keys) {
		if keys[k].IsBinary() { // бинарный файл в .env не лезет — доставать get --out
			binSkipped = append(binSkipped, k)
			continue
		}
		b.WriteString(dotenv.Line(k, keys[k].Value) + "\n")
		written = append(written, k)
	}
	if len(written) == 0 {
		die("в %s только бинарные (файловые) ключи — .env не из чего собрать (sec get %s/<KEY> --out <файл>)", proj, proj)
	}
	if err := writeFile0600(file, []byte(b.String())); err != nil {
		die("запись %s: %v", file, err)
	}
	if len(binSkipped) > 0 {
		fmt.Fprintf(os.Stderr, "sec: бинарные (файловые) ключи в .env не пишутся, пропущены: %s (sec get %s/<KEY> --out)\n",
			strings.Join(binSkipped, ", "), proj)
	}
	audit.Record("export", proj, "→ "+file)
	fmt.Printf("записан %s (0600): %s\n", file, strings.Join(written, ", "))
	return 0
}

// looksLikeJSON — позиционный аргумент import это сам JSON, а не путь/проект.
func looksLikeJSON(arg string) bool {
	return strings.HasPrefix(strings.TrimLeft(arg, " \t\r\n\ufeff"), "{")
}

// looksLikePath — позиционный аргумент import похож на путь к файлу, а не на
// имя проекта: слэш, ведущая точка/тильда, либо такой файл реально есть рядом
// (`sec import prod.env` — имя проекта тоже валидное, решает наличие файла).
func looksLikePath(arg string) bool {
	if arg == "" {
		return false
	}
	if strings.ContainsAny(arg, "/\\") || strings.HasPrefix(arg, ".") || strings.HasPrefix(arg, "~") {
		return true
	}
	fi, err := os.Stat(arg)
	return err == nil && !fi.IsDir()
}

func importCommand(args []string) int {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	var file, inline string
	var fromInfisical, fromJSON, fromClipboard bool
	var ienv, path, projectID, token string
	fs.StringVar(&file, "file", "", "путь к файлу .env или JSON (умолч. .env; можно позиционно, '-' — stdin)")
	fs.BoolVar(&fromJSON, "from-json", false, "разбирать источник как JSON, не угадывая формат")
	fs.BoolVar(&fromClipboard, "clipboard", false, "источник — буфер обмена (.env или JSON)")
	fs.BoolVar(&fromInfisical, "from-infisical", false, "источник — Infisical (через их CLI), а не файл")
	fs.StringVar(&ienv, "infisical-env", "", "Infisical: окружение (умолч. — значение -e, иначе dev)")
	fs.StringVar(&path, "path", "/", "Infisical: путь к папке секретов")
	fs.StringVar(&projectID, "projectId", "", "Infisical: id проекта (иначе из .infisical.json в текущей папке)")
	fs.StringVar(&token, "token", "", "Infisical: сервис-токен/идентификатор (иначе текущий логин)")
	getEnv := addEnvFlag(fs)

	// позиционные: [proj] и/или источник (путь, "-" или сам JSON), в любом порядке
	var service string
	for _, a := range collectPositionals(fs, args) {
		switch {
		case looksLikeJSON(a):
			if inline != "" {
				die("JSON передан дважды")
			}
			inline = a
		case a == "-" || looksLikePath(a):
			if file != "" {
				die("файл указан дважды: %s и %s", file, a)
			}
			file = a
		case service == "":
			service = a
		default:
			die(`лишний аргумент %q: sec import [proj] [path/to/.env | - | '{"KEY":"…"}']`, a)
		}
	}
	sources := 0
	for _, given := range []bool{inline != "", file != "", fromClipboard} {
		if given {
			sources++
		}
	}
	if sources > 1 {
		die("источник указан несколько раз — выбери одно: файл, stdin, --clipboard или JSON аргументом")
	}
	if service == "" {
		service = cwdProject()
	}
	secEnv := resolvedEnv(getEnv(), service)
	target := resolveProj(service, secEnv) // куда в sec: service либо service@env

	if fromInfisical {
		if ienv == "" { // дефолт Infisical-окружения — sec-инстанс, иначе dev
			if ienv = secEnv; ienv == "" {
				ienv = "dev"
			}
		}
		return importFromInfisical(target, ienv, path, projectID, token)
	}

	data, label, path := importSource(inline, file, fromClipboard, service)
	kv, warns := parseImport(data, fromJSON)
	for _, w := range warns {
		fmt.Fprintf(os.Stderr, "sec: %s: %s\n", label, w)
	}
	if len(kv) == 0 {
		die("в %s не нашлось ни одной пары KEY=VALUE", label)
	}
	writeImported(target, kv, "из "+label)
	if path != "" {
		fmt.Fprintf(os.Stderr, "исходный файл остался на диске — удали, если больше не нужен: rm %s\n", path)
	}
	return 0
}

// importSource достаёт текст источника и его подпись для сообщений: JSON из
// аргумента, буфер обмена, stdin (явный "-" или пайп) либо файл (умолч. .env).
// Третий результат — путь к файлу, если источником был файл (иначе "").
func importSource(inline, file string, fromClipboard bool, service string) (data, label, path string) {
	switch {
	case inline != "":
		fmt.Fprintf(os.Stderr, "sec: JSON пришёл аргументом — значения осели в истории shell и видны в ps;\n"+
			"    безопаснее пайпом: cat creds.json | sec import %s\n", service)
		return inline, "аргумента", ""
	case fromClipboard:
		s, err := clipboardRead()
		if err != nil {
			die("буфер обмена: %v", err)
		}
		if strings.TrimSpace(s) == "" {
			die("буфер обмена пуст")
		}
		return s, "буфера обмена", ""
	case file == "-" || (file == "" && stdinPiped()):
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			die("чтение stdin: %v", err)
		}
		return string(b), "stdin", ""
	default:
		if file == "" {
			file = ".env"
		}
		b, err := os.ReadFile(file)
		if err != nil {
			die("чтение %s: %v", file, err)
		}
		return string(b), file, file
	}
}

// parseImport выбирает формат источника: JSON, если попросили явно или текст
// начинается с '{', иначе .env-диалект.
func parseImport(data string, forceJSON bool) (map[string]string, []string) {
	if !forceJSON && !looksLikeJSON(data) {
		return dotenv.Parse(data)
	}
	kv, warns, err := dotenv.ParseJSON(data)
	if err != nil {
		die("%v", err)
	}
	return kv, warns
}

// writeImported вливает набор KEY=VALUE в проект (общее для import из .env и из
// Infisical): существующие значения уходят в историю, новые добавляются.
func writeImported(proj string, kv map[string]string, source string) (int, int) {
	unlock := store.Lock()
	defer unlock()
	st, mkey, _, err := store.Open(true)
	if err != nil {
		die("%v", err)
	}
	keys := st.Project(proj)
	added, updated, skipped := 0, 0, 0
	for k, v := range kv {
		if editBlock(st, proj, k) != "" { // ссылку/наследование не перетираем импортом
			fmt.Fprintf(os.Stderr, "sec: %s/%s пропущен — ссылка/наследование (перебить: sec set %s/%s --override)\n", proj, k, proj, k)
			skipped++
			continue
		}
		if store.Put(keys, k, v) {
			updated++
		} else {
			added++
		}
	}
	if err := store.Save(st, mkey); err != nil {
		die("запись хранилища: %v", err)
	}
	audit.Record("import", proj, fmt.Sprintf("%s (новых %d, обновлено %d, пропущено %d)", source, added, updated, skipped))
	tail := ""
	if skipped > 0 {
		tail = fmt.Sprintf(", пропущено ссылок/наследования %d", skipped)
	}
	fmt.Printf("импортировано в %s: %s (новых %d, обновлено %d%s)\n",
		proj, strings.Join(store.SortedKeys(kv), ", "), added, updated, tail)
	return added, updated
}

// logCommand показывает журнал обращений (значений там нет — только имена).
func logCommand(args []string) int {
	filter, rest := splitArgs(args)
	fs := flag.NewFlagSet("log", flag.ExitOnError)
	var n int
	var asJSON bool
	fs.IntVar(&n, "n", 20, "сколько последних записей показать")
	fs.BoolVar(&asJSON, "json", false, "машинный вывод JSON")
	_ = fs.Parse(rest)
	if filter == "" {
		filter = fs.Arg(0)
	}

	entries := audit.Read()
	if filter != "" {
		var out []audit.Entry
		for _, e := range entries {
			if e.Target == filter || strings.HasPrefix(e.Target, filter+"/") ||
				strings.HasPrefix(e.Target, filter+"@") {
				out = append(out, e)
			}
		}
		entries = out
	}
	if len(entries) > n {
		entries = entries[len(entries)-n:]
	}
	if asJSON {
		if entries == nil {
			entries = []audit.Entry{}
		}
		data, _ := json.MarshalIndent(entries, "", "  ")
		fmt.Println(string(data))
		return 0
	}
	if len(entries) == 0 {
		fmt.Println("журнал пуст")
		return 0
	}
	for _, e := range entries {
		line := fmt.Sprintf("%s  %-7s %-28s %-30s", fmtTime(e.TS), e.Op, e.Target, e.Detail)
		if e.By != "" {
			line += "← " + e.By
		}
		fmt.Println(strings.TrimRight(line, " "))
	}
	return 0
}

func infoCommand(args []string) int {
	fs := flag.NewFlagSet("info", flag.ExitOnError)
	var asJSON bool
	fs.BoolVar(&asJSON, "json", false, "машинный вывод JSON")
	_ = fs.Parse(args)

	out := struct {
		Store    string `json:"store"`
		Size     int64  `json:"size"`
		Backend  string `json:"backend"`
		Audit    string `json:"audit"`
		Error    string `json:"error,omitempty"`
		Projects int    `json:"projects"`
		Keys     int    `json:"keys"`
	}{Store: store.Path(), Backend: "none", Audit: audit.Path()}
	if fi, err := os.Stat(store.Path()); err == nil {
		out.Size = fi.Size()
	}
	store, _, backend, err := store.Open(false)
	if err != nil {
		out.Error = err.Error()
	} else {
		out.Backend = backend
		out.Projects = len(store.Projects)
		for _, keys := range store.Projects {
			out.Keys += len(keys)
		}
	}

	if asJSON {
		data, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(data))
		return 0
	}
	fmt.Printf("хранилище:   %s (%d байт)\n", out.Store, out.Size)
	fmt.Printf("журнал:      %s\n", out.Audit)
	if out.Error != "" {
		fmt.Printf("мастер-ключ: %s\n", out.Error)
		return 0
	}
	switch out.Backend {
	case "keyring":
		fmt.Printf("мастер-ключ: %s\n", keyring.OSName())
	case "env":
		fmt.Println("мастер-ключ: env SEC_KEY")
	case "file":
		fmt.Printf("мастер-ключ: файл %s\n", keyring.FilePath())
	}
	fmt.Printf("проектов:    %d, ключей: %d\n", out.Projects, out.Keys)
	return 0
}
