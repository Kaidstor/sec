package command

// Несекретные метаданные ключа (meta) и отчёты по ротации (stale / doctor).
// Метаданные описывают ключ, а не значение: назначение, где крутить, как часто.
// Значения секретов здесь не участвуют.

import (
	"github.com/kaidstor/sec/internal/audit"
	"github.com/kaidstor/sec/internal/store"

	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// parseHumanDuration понимает интервалы вида "90d", "2w", а также стандартные
// go-длительности ("12h", "30m"). Дни/недели go сам не умеет.
func parseHumanDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("пустой интервал")
	}
	switch s[len(s)-1] {
	case 'd', 'D':
		n, err := strconv.Atoi(strings.TrimSpace(s[:len(s)-1]))
		if err != nil {
			return 0, fmt.Errorf("некорректный интервал %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	case 'w', 'W':
		n, err := strconv.Atoi(strings.TrimSpace(s[:len(s)-1]))
		if err != nil {
			return 0, fmt.Errorf("некорректный интервал %q", s)
		}
		return time.Duration(n) * 7 * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

// resolveExpiresAt превращает "YYYY-MM-DD" или интервал ("30d") в RFC3339.
func resolveExpiresAt(s string) (string, error) {
	s = strings.TrimSpace(s)
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t.Format(time.RFC3339), nil
	}
	d, err := parseHumanDuration(s)
	if err != nil {
		return "", fmt.Errorf("не дата (YYYY-MM-DD) и не интервал: %q", s)
	}
	return time.Now().Add(d).Format(time.RFC3339), nil
}

// dueAt возвращает момент, к которому секрет пора ротировать, и его источник:
// явный ExpiresAt приоритетнее вычисленного из RotateEvery. ok=false — политики нет.
func dueAt(s store.Secret) (time.Time, string, bool) {
	if s.Meta == nil {
		return time.Time{}, "", false
	}
	if s.Meta.ExpiresAt != "" {
		if t, err := time.Parse(time.RFC3339, s.Meta.ExpiresAt); err == nil {
			return t, "expires", true
		}
	}
	if s.Meta.RotateEvery != "" {
		if d, err := parseHumanDuration(s.Meta.RotateEvery); err == nil {
			if base, err := time.Parse(time.RFC3339, s.UpdatedAt); err == nil {
				return base.Add(d), "rotate-every", true
			}
		}
	}
	return time.Time{}, "", false
}

func metaCommand(args []string) int {
	ref, rest := splitArgs(args)
	fs := flag.NewFlagSet("meta", flag.ExitOnError)
	var note, kind, rotateURL, rotateEvery, expires string
	var clear, asJSON bool
	fs.StringVar(&note, "note", "", "описание/назначение (без секрета)")
	fs.StringVar(&kind, "kind", "", "тип: password|apikey|totp|env|...")
	fs.StringVar(&rotateURL, "rotate-url", "", "где крутить секрет")
	fs.StringVar(&rotateEvery, "rotate-every", "", "интервал ротации, напр. 90d")
	fs.StringVar(&expires, "expires", "", "дедлайн: дата YYYY-MM-DD или интервал от сейчас (30d)")
	fs.BoolVar(&clear, "clear", false, "снять все метаданные")
	fs.BoolVar(&asJSON, "json", false, "показать метаданные в JSON")
	getEnv := addEnvFlag(fs)
	_ = fs.Parse(rest)
	proj, key := resolveKeyRef(ref, fs, getEnv(), "sec meta <proj>/<KEY> [--note ... --kind ... --rotate-every 90d]")

	setf := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { setf[f.Name] = true })
	mutating := clear || setf["note"] || setf["kind"] || setf["rotate-url"] || setf["rotate-every"] || setf["expires"]

	if !mutating {
		st, _, _, err := store.Open(false)
		if err != nil {
			die("%v", err)
		}
		if own, ok := st.Projects[proj][key]; ok { // собственный ключ (в т.ч. ссылка) — своя мета
			printMeta(proj, key, own, asJSON)
			return 0
		}
		sec, _, source, found := st.Lookup(proj, key) // унаследованный — мета родителя
		if !found {
			die("нет %s/%s", proj, key)
		}
		if !asJSON {
			fmt.Printf("%s/%s: метаданные наследуются из %s\n", proj, key, source)
		}
		printMeta(proj, key, sec, asJSON)
		return 0
	}

	unlock := store.Lock()
	defer unlock()
	st, mkey, _, err := store.Open(false)
	if err != nil {
		die("%v", err)
	}
	if _, ok := st.Projects[proj][key]; !ok {
		if _, org, source, found := st.Lookup(proj, key); found && org == store.OriginExtend {
			die("%s/%s наследуется из %s — правь метаданные в родителе: sec meta %s", proj, key, source, store.RefToCLI(source))
		}
	}
	sec := mustSecret(st, proj, key)
	if clear {
		sec.Meta = nil
	} else {
		m := store.Meta{}
		if sec.Meta != nil {
			m = *sec.Meta
		}
		if setf["note"] {
			m.Note = note
		}
		if setf["kind"] {
			m.Kind = kind
		}
		if setf["rotate-url"] {
			m.RotateURL = rotateURL
		}
		if setf["rotate-every"] {
			if rotateEvery != "" {
				if _, err := parseHumanDuration(rotateEvery); err != nil {
					die("--rotate-every: %v", err)
				}
			}
			m.RotateEvery = rotateEvery
		}
		if setf["expires"] {
			if expires == "" {
				m.ExpiresAt = ""
			} else {
				v, err := resolveExpiresAt(expires)
				if err != nil {
					die("--expires: %v", err)
				}
				m.ExpiresAt = v
			}
		}
		if m == (store.Meta{}) {
			sec.Meta = nil
		} else {
			sec.Meta = &m
		}
	}
	st.Projects[proj][key] = sec
	if err := store.Save(st, mkey); err != nil {
		die("запись хранилища: %v", err)
	}
	audit.Record("meta", proj+"/"+key, "")
	printMeta(proj, key, sec, asJSON)
	return 0
}

func printMeta(proj, key string, sec store.Secret, asJSON bool) {
	if asJSON {
		out := struct {
			Ref  string      `json:"ref"`
			Meta *store.Meta `json:"meta"`
		}{proj + "/" + key, sec.Meta}
		data, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(data))
		return
	}
	if sec.Meta == nil {
		fmt.Printf("%s/%s: метаданных нет\n", proj, key)
		return
	}
	m := sec.Meta
	fmt.Printf("%s/%s\n", proj, key)
	if m.Kind != "" {
		fmt.Printf("  тип:       %s\n", m.Kind)
	}
	if m.Note != "" {
		fmt.Printf("  заметка:   %s\n", m.Note)
	}
	if m.RotateURL != "" {
		fmt.Printf("  ротация:   %s\n", m.RotateURL)
	}
	if m.RotateEvery != "" {
		fmt.Printf("  интервал:  %s\n", m.RotateEvery)
	}
	if due, src, ok := dueAt(sec); ok {
		status := "ок"
		if time.Now().After(due) {
			status = "ПРОСРОЧЕНО"
		}
		fmt.Printf("  крутить до: %s (%s, %s)\n", fmtTime(due.Format(time.RFC3339)), src, status)
	}
}

// staleCommand перечисляет секреты, которые пора ротировать: просроченные по
// политике (expires / rotate-every) либо старше порога --older-than.
func staleCommand(args []string) int {
	service, rest := splitArgs(args)
	fs := flag.NewFlagSet("stale", flag.ExitOnError)
	var olderThan string
	var asJSON bool
	fs.StringVar(&olderThan, "older-than", "", "порог возраста для ключей без политики, напр. 90d")
	fs.BoolVar(&asJSON, "json", false, "машинный вывод")
	getEnv := addEnvFlag(fs)
	_ = fs.Parse(rest)
	if service == "" {
		service = fs.Arg(0)
	}
	env := getEnv() // явный -e фильтрует инстанс; без него — все инстансы сервиса
	checkEnv(env)

	var threshold time.Duration
	if olderThan != "" {
		d, err := parseHumanDuration(olderThan)
		if err != nil {
			die("--older-than: %v", err)
		}
		threshold = d
	}

	st, _, _, err := store.Open(false)
	if err != nil {
		die("%v", err)
	}
	now := time.Now()

	type staleItem struct {
		Ref    string `json:"ref"`
		Reason string `json:"reason"`
		Age    string `json:"age"`
	}
	var items []staleItem
	for _, p := range store.SortedKeys(st.Projects) {
		base, penv := store.BaseAndEnv(p)
		if service != "" && base != service {
			continue
		}
		if env != "" && penv != env {
			continue
		}
		keys := st.Projects[p]
		for _, k := range store.SortedKeys(keys) {
			sec := keys[k]
			if sec.Ref != "" {
				continue // ссылка — ротируется у родителя
			}
			ref := p + "/" + k
			if due, src, ok := dueAt(sec); ok {
				if now.After(due) {
					items = append(items, staleItem{ref, "просрочено (" + src + ")", fmtSince(due, now) + " назад"})
				}
				continue // есть политика — порог по возрасту к нему не применяем
			}
			if threshold > 0 {
				if t, err := time.Parse(time.RFC3339, sec.UpdatedAt); err == nil && now.Sub(t) > threshold {
					items = append(items, staleItem{ref, "старше " + olderThan, fmtSince(t, now)})
				}
			}
		}
	}

	if asJSON {
		data, _ := json.MarshalIndent(items, "", "  ")
		fmt.Println(string(data))
		return 0
	}
	if len(items) == 0 {
		fmt.Println("нечего ротировать")
		return 0
	}
	for _, it := range items {
		fmt.Printf("%-36s %-24s %s\n", it.Ref, it.Reason, it.Age)
	}
	return 2 // ненулевой код — удобно как гейт в CI/скриптах
}

// fmtSince — грубый человекочитаемый возраст (дни).
func fmtSince(from, to time.Time) string {
	days := int(to.Sub(from).Hours() / 24)
	if days <= 0 {
		return "сегодня"
	}
	return fmt.Sprintf("%d дн.", days)
}

// doctorCommand — здоровье хранилища: права файла, бэкенд ключа, доступность
// журнала, дубли значений (по отпечатку), сколько ключей пора ротировать.
func doctorCommand(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	_ = fs.Parse(args)

	problems := 0
	warn := func(format string, a ...any) {
		problems++
		fmt.Printf("  ✗ "+format+"\n", a...)
	}
	okline := func(format string, a ...any) { fmt.Printf("  ✓ "+format+"\n", a...) }

	// права файла хранилища: unix — POSIX 0600, Windows — DACL без широких групп
	// (реализации — perms_unix.go / perms_windows.go)
	if fi, err := os.Stat(store.Path()); err == nil {
		if msg, ok := storePermsStatus(store.Path(), fi); ok {
			okline("%s", msg)
		} else {
			warn("%s", msg)
		}
	}

	st, mkey, backend, err := store.Open(false)
	if err != nil {
		warn("хранилище недоступно: %v", err)
		fmt.Printf("итог: проблем — %d\n", problems)
		return boolToCode(problems > 0)
	}
	okline("мастер-ключ: бэкенд %s", backend)

	// доступность журнала на запись
	if f, err := os.OpenFile(audit.Path(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
		_ = f.Close()
		okline("журнал доступен на запись")
	} else {
		warn("журнал недоступен: %v", err)
	}

	// дубли значений по отпечатку
	fps := map[string][]string{}
	total := 0
	for _, p := range store.SortedKeys(st.Projects) {
		for _, k := range store.SortedKeys(st.Projects[p]) {
			s := st.Projects[p][k]
			if s.Ref != "" {
				continue // ссылка — своего значения нет, дубли ищем у родителя
			}
			total++
			fp := store.Fingerprint(mkey, s.Value)
			fps[fp] = append(fps[fp], p+"/"+k)
		}
	}
	dups := 0
	for _, refs := range fps {
		if len(refs) > 1 {
			dups++
			warn("одинаковое значение у: %s", strings.Join(refs, ", "))
		}
	}
	if dups == 0 {
		okline("дублей значений нет (%d ключей)", total)
	}

	// сколько пора ротировать
	now := time.Now()
	stale := 0
	for _, p := range st.Projects {
		for _, sec := range p {
			if due, _, ok := dueAt(sec); ok && now.After(due) {
				stale++
			}
		}
	}
	if stale > 0 {
		warn("пора ротировать: %d (подробнее: sec stale)", stale)
	} else {
		okline("просроченных по политике нет")
	}

	fmt.Printf("итог: проблем — %d\n", problems)
	return boolToCode(problems > 0)
}

// applyMetaFlags навешивает note/kind на ключ при создании (set/gen), не
// затирая уже заданные метаданные. Пустые значения игнорируются.
func applyMetaFlags(keys map[string]store.Secret, key, note, kind string) {
	if note == "" && kind == "" {
		return
	}
	e := keys[key]
	m := store.Meta{}
	if e.Meta != nil {
		m = *e.Meta
	}
	if note != "" {
		m.Note = note
	}
	if kind != "" {
		m.Kind = kind
	}
	e.Meta = &m
	keys[key] = e
}

func timeNowAfter(t time.Time) bool { return time.Now().After(t) }

func boolToCode(b bool) int {
	if b {
		return 1
	}
	return 0
}
