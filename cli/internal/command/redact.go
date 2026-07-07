package command

// redact: вычистить сохранённые значения секретов из произвольного текста —
// чтобы безопасно показать лог/дифф/вывод команды, не рискуя утащить значение
// в чат агента. В отличие от scan (который только находит утечки и падает
// ненулевым кодом), redact отдаёт очищенный текст: каждое встреченное значение
// заменяется на [redacted:proj/KEY]. Вывод по построению безопасен — секретов
// в нём не остаётся.
//
//	cmd 2>&1 | sec redact                очистить stdin → stdout
//	sec redact app.log other.log         очистить файлы → stdout
//	sec redact app.log --file safe.log   записать результат в файл
//
// Как и scan, redact знает только значения, лежащие в сторе: секрет, которого
// в sec нет, он не увидит. Это не универсальный DLP, а страховка от утечки
// собственных сохранённых значений.

import (
	"github.com/kaidstor/sec/internal/audit"
	"github.com/kaidstor/sec/internal/store"

	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// replacement — одно значение и на что его менять; refs нужны для сводки/журнала.
type replacement struct {
	value       string
	placeholder string
	refs        []string
}

func redactCommand(args []string) int {
	fs := flag.NewFlagSet("redact", flag.ExitOnError)
	var minLen int
	var withHistory, mask bool
	var outFile string
	fs.IntVar(&minLen, "min", 8, "игнорировать значения короче N символов (шум)")
	fs.BoolVar(&withHistory, "history", false, "чистить и прошлые значения из истории, не только текущие")
	fs.BoolVar(&mask, "mask", false, "заменять на [redacted] без имени ключа")
	fs.StringVar(&outFile, "file", "", "записать результат в файл 0600 (умолч. — stdout)")
	// collectPositionals — чтобы флаги работали и после путей (sec redact a.log --file out).
	paths := collectPositionals(fs, args)

	if len(paths) == 0 && !stdinPiped() {
		die("подай текст в stdin (cmd | sec redact) или укажи файлы (sec redact app.log)")
	}

	st, _, _, err := store.Open(false)
	if err != nil {
		die("%v", err)
	}
	values, skipped := collectStoreValues(st, minLen, withHistory)
	if skipped > 0 {
		fmt.Fprintf(os.Stderr, "sec: пропущено значений короче %d символов: %d (чистить всё: --min 1)\n", minLen, skipped)
	}
	repls := buildReplacements(values, mask)

	// Куда пишем результат: файл 0600 или stdout. Вывод безопасен (секретов нет),
	// но 0600 держим консистентно с export/render.
	var w io.Writer = os.Stdout
	if outFile != "" {
		f, err := os.OpenFile(outFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			die("запись %s: %v", outFile, err)
		}
		defer f.Close()
		w = f
	}

	hit := map[string]bool{}
	src := "stdin"
	switch {
	case len(paths) == 0, len(paths) == 1 && paths[0] == "-":
		if err := redactReader(os.Stdin, w, repls, hit); err != nil {
			die("чтение stdin: %v", err)
		}
	default:
		src = strings.Join(paths, ", ")
		for _, p := range paths {
			if err := redactPath(p, w, repls, hit); err != nil {
				die("%s: %v", p, err)
			}
		}
	}

	report(hit)
	audit.Record("redact", src, fmt.Sprintf("скрыто ключей: %d", len(hit)))
	return 0
}

// redactPath открывает файл (или stdin для "-") и прогоняет его через redactReader.
func redactPath(path string, w io.Writer, repls []replacement, hit map[string]bool) error {
	if path == "-" {
		return redactReader(os.Stdin, w, repls, hit)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return redactReader(f, w, repls, hit)
}

// redactReader копирует r в w построчно, заменяя каждое сохранённое значение на
// его плейсхолдер. Читает через ReadString('\n'), поэтому длина строки не
// ограничена (минифицированный JSON/JS не обрывается), а в памяти держится не
// больше одной строки. Значения секретов переносов не содержат, так что
// построчная замена корректна. Встреченные refs копятся в hit.
func redactReader(r io.Reader, w io.Writer, repls []replacement, hit map[string]bool) error {
	br := bufio.NewReader(r)
	bw := bufio.NewWriter(w)
	for {
		line, err := br.ReadString('\n')
		if len(line) > 0 {
			for _, rp := range repls {
				if strings.Contains(line, rp.value) {
					line = strings.ReplaceAll(line, rp.value, rp.placeholder)
					for _, ref := range rp.refs {
						hit[ref] = true
					}
				}
			}
			if _, werr := bw.WriteString(line); werr != nil {
				return werr
			}
		}
		if err != nil {
			if err == io.EOF {
				return bw.Flush()
			}
			_ = bw.Flush()
			return err
		}
	}
}

// buildReplacements превращает карту «значение → refs» в список замен,
// отсортированный по убыванию длины значения: длинные меняем первыми, чтобы
// значение, содержащее внутри более короткое, заменилось целиком.
func buildReplacements(values map[string][]string, mask bool) []replacement {
	repls := make([]replacement, 0, len(values))
	for val, refs := range values {
		repls = append(repls, replacement{val, placeholderFor(refs, mask), refs})
	}
	sort.Slice(repls, func(i, j int) bool {
		if len(repls[i].value) != len(repls[j].value) {
			return len(repls[i].value) > len(repls[j].value)
		}
		return repls[i].value < repls[j].value // стабильный порядок при равной длине
	})
	return repls
}

// placeholderFor строит плейсхолдер для значения. По умолчанию раскрывает имя
// ключа (имена безопасны для чата): [redacted:whois/API_TOKEN]; при mask —
// глухое [redacted]. Если одно значение принадлежит нескольким ключам, к первому
// добавляется "+N".
func placeholderFor(refs []string, mask bool) string {
	if mask || len(refs) == 0 {
		return "[redacted]"
	}
	label := compactRef(refs[0])
	if len(refs) > 1 {
		label += fmt.Sprintf("+%d", len(refs)-1)
	}
	return "[redacted:" + label + "]"
}

// compactRef переводит внутренний адрес "service@env/KEY" в компактную форму без
// пробелов для инлайн-плейсхолдера: "service/KEY" или "service/KEY@env" (в
// отличие от RefToCLI, которая даёт "service/KEY -e env" для подсказок). Суффикс
// ~prev (значение из истории) сохраняется.
func compactRef(internal string) string {
	suffix := ""
	if strings.HasSuffix(internal, "~prev") {
		internal = strings.TrimSuffix(internal, "~prev")
		suffix = "~prev"
	}
	i := strings.LastIndexByte(internal, '/')
	if i <= 0 || i == len(internal)-1 {
		return internal + suffix
	}
	proj, key := internal[:i], internal[i+1:]
	svc, env := store.BaseAndEnv(proj)
	if env == "" {
		return svc + "/" + key + suffix
	}
	return svc + "/" + key + "@" + env + suffix
}

// report печатает в stderr сводку о вычищенных ключах (имена безопасны). В
// stdout идёт только очищенный текст, поэтому сводка не мешает пайпу.
func report(hit map[string]bool) {
	if len(hit) == 0 {
		fmt.Fprintln(os.Stderr, "sec: совпадений нет — вывод идентичен вводу")
		return
	}
	refs := make([]string, 0, len(hit))
	for ref := range hit {
		refs = append(refs, compactRef(ref))
	}
	sort.Strings(refs)
	fmt.Fprintf(os.Stderr, "sec: скрыто ключей: %d (%s)\n", len(hit), strings.Join(refs, ", "))
}
