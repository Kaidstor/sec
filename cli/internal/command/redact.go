package command

// redact: вычистить секреты из произвольного текста — чтобы показать лог/дифф/
// вывод команды, не утащив значение в чат агента. В отличие от scan (который
// только находит утечки и падает ненулевым кодом), redact отдаёт очищенный
// текст. Два слоя:
//
//   - значения из стора → [redacted:proj/KEY];
//   - правила для того, чего в сторе нет (redact_rules.go): значение поля с
//     секретным именем → [redacted:field], пароль в URI → [redacted:uri], тело
//     приватного PEM-ключа → [redacted:pem]. Выключаются --store-only.
//
//	cmd 2>&1 | sec redact                очистить stdin → stdout
//	sec redact app.log other.log         очистить файлы → stdout
//	sec redact app.log --file safe.log   записать результат в файл
//	sec redact --strict <dump.json       код 1, если нашлись секреты не из стора
//
// Полноты redact не гарантирует: секрет в поле с невинным именем и формат,
// которого правила не знают, пройдут как есть. Приватный документ целиком через
// redact не показывать — выбирать из него нужные поля программно.

import (
	"github.com/kaidstor/sec/internal/audit"
	"github.com/kaidstor/sec/internal/store"

	"bufio"
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
	fs := newFlagSet("redact")
	var minLen int
	var withHistory, mask, includeConfig, storeOnly, strict bool
	var outFile string
	fs.IntVar(&minLen, "min", 8, "игнорировать значения короче N символов (шум)")
	fs.BoolVar(&withHistory, "history", false, "чистить и прошлые значения из истории, не только текущие")
	fs.BoolVar(&includeConfig, "include-config", false, "чистить и несекретные значения kind: config")
	fs.BoolVar(&mask, "mask", false, "значения стора — глухим [redacted] без имени ключа")
	fs.BoolVar(&storeOnly, "store-only", false, "только значения из стора, без правил по именам полей, URI и PEM")
	fs.BoolVar(&strict, "strict", false, "код 1, если правила нашли секреты, которых нет в сторе")
	fs.StringVar(&outFile, "file", "", "записать результат в файл 0600 (умолч. — stdout)")
	// collectPositionals — чтобы флаги работали и после путей (sec redact a.log --file out).
	paths := collectPositionals(fs, args)

	if len(paths) == 0 && !stdinPiped() {
		die("подай текст в stdin (cmd | sec redact) или укажи файлы (sec redact app.log)")
	}
	if strict && storeOnly {
		die("--strict проверяет находки правил, а --store-only их выключает — выбери одно")
	}

	st, _, _, err := store.Open(false)
	if err != nil {
		dieStore(err)
	}
	values, skips := collectStoreValues(st, storeScope{minLen: minLen, withHistory: withHistory, includeConfig: includeConfig})
	reportScanSkips(skips, minLen)
	rd := newRedactor(buildReplacements(values, mask), !storeOnly)

	// Куда пишем результат: файл 0600 или stdout. 0600 — как у export/render:
	// полноты чистки redact не гарантирует.
	var w io.Writer = stdout
	if outFile != "" {
		f, err := os.OpenFile(outFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			dieK(kindIO, "запись %s: %v", outFile, err)
		}
		defer f.Close()
		w = f
	}

	src := "stdin"
	switch {
	case len(paths) == 0, len(paths) == 1 && paths[0] == "-":
		if err := rd.copy(os.Stdin, w); err != nil {
			dieK(kindIO, "чтение stdin: %v", err)
		}
	default:
		src = strings.Join(paths, ", ")
		for _, p := range paths {
			if err := redactPath(p, w, rd); err != nil {
				dieK(kindIO, "%s: %v", p, err)
			}
		}
	}

	rd.report()
	audit.Record("redact", src, fmt.Sprintf("скрыто ключей стора: %d, по правилам: %d", len(rd.hit), rd.stats.total()))
	out := map[string]any{"hidden": store.SortedKeys(rd.hit)}
	if rd.rules {
		out["rules"] = map[string]any{"fields": store.SortedKeys(rd.stats.fields), "uri": rd.stats.uri, "pem": rd.stats.pem}
	}
	if outFile != "" {
		out["file"] = outFile
	} else {
		out["text"] = captured.String() // очищенный текст: в JSON-режиме stdout — этот буфер
	}
	emit(out)
	if strict && rd.stats.total() > 0 {
		warnf("--strict: в тексте были секреты, которых нет в сторе")
		return 1
	}
	return 0
}

func redactPath(path string, w io.Writer, rd *redactor) error {
	if path == "-" {
		return rd.copy(os.Stdin, w)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return rd.copy(f, w)
}

// redactor — состояние чистки на весь вывод: какие ключи стора встретились,
// что нашли правила и не внутри ли мы PEM-блока (он многострочный).
type redactor struct {
	repls []replacement
	rules bool
	hit   map[string]bool
	stats ruleStats
	inPEM bool
}

func newRedactor(repls []replacement, rules bool) *redactor {
	return &redactor{repls: repls, rules: rules, hit: map[string]bool{}, stats: ruleStats{fields: map[string]int{}}}
}

func (rd *redactor) line(line string) string {
	if rd.inPEM {
		line, rd.inPEM = pemTail(line)
		if rd.inPEM {
			return ""
		}
	}
	for _, rp := range rd.repls {
		if strings.Contains(line, rp.value) {
			line = strings.ReplaceAll(line, rp.value, rp.placeholder)
			for _, ref := range rp.refs {
				rd.hit[ref] = true
			}
		}
	}
	if rd.rules {
		line, rd.inPEM = applyRules(line, &rd.stats)
	}
	return line
}

// copy копирует r в w построчно через line. ReadString('\n') не ограничивает
// длину строки (минифицированный JSON/JS не обрывается), в памяти — не больше
// одной строки. Значения стора переносов не содержат, так что построчная
// замена для них корректна; многострочный PEM ведёт inPEM.
func (rd *redactor) copy(r io.Reader, w io.Writer) error {
	br := bufio.NewReader(r)
	bw := bufio.NewWriter(w)
	for {
		line, err := br.ReadString('\n')
		if len(line) > 0 {
			if _, werr := bw.WriteString(rd.line(line)); werr != nil {
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
// добавляется "+N". Адрес — внутренний "service[@profile]/KEY[~prev]", он же
// CLI-форма, пробелов не содержит.
func placeholderFor(refs []string, mask bool) string {
	if mask || len(refs) == 0 {
		return redactedTag + "]"
	}
	label := refs[0]
	if len(refs) > 1 {
		label += fmt.Sprintf("+%d", len(refs)-1)
	}
	return redactedLabel(label)
}

// report печатает в stderr сводку (имена ключей и полей безопасны). В stdout
// идёт только очищенный текст, поэтому сводка не мешает пайпу. «Ничего не
// скрыто» не значит «секретов нет» — сводка говорит это прямо.
func (rd *redactor) report() {
	if jsonMode { // в JSON — поля hidden и rules
		return
	}
	if len(rd.hit) > 0 {
		warnf("скрыто значений из стора: %d (%s)", len(rd.hit), strings.Join(store.SortedKeys(rd.hit), ", "))
	}
	if rd.stats.total() > 0 {
		var parts []string
		if len(rd.stats.fields) > 0 {
			parts = append(parts, "поля "+strings.Join(store.SortedKeys(rd.stats.fields), ", "))
		}
		if rd.stats.uri > 0 {
			parts = append(parts, fmt.Sprintf("пароли в URI: %d", rd.stats.uri))
		}
		if rd.stats.pem > 0 {
			parts = append(parts, fmt.Sprintf("PEM-ключи: %d", rd.stats.pem))
		}
		warnf("скрыто по правилам, в сторе этих значений нет: %s", strings.Join(parts, "; "))
	}
	if len(rd.hit) == 0 && rd.stats.total() == 0 {
		if rd.rules {
			warnf("ничего не скрыто — вывод идентичен вводу. Секрет в поле с невинным именем redact не видит")
		} else {
			warnf("значений из стора нет — вывод идентичен вводу; с --store-only секреты не из стора не ищутся")
		}
	}
}
