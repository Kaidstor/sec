package command

import (
	"bytes"
	"strings"
	"testing"

	"github.com/kaidstor/sec/internal/store"
)

func redactStore() *store.Store {
	return &store.Store{Version: 1, Projects: map[string]map[string]store.Secret{
		"whois":   {"API_TOKEN": {Value: "supersecretvalue123"}},
		"db@prod": {"PASSWORD": {Value: "hunter2hunter2pw"}},
		"app":     {"SHORT": {Value: "abc"}, "REFD": {Ref: "whois/API_TOKEN"}},
	}}
}

func redactText(t *testing.T, st *store.Store, in string, minLen int, withHistory, mask bool) (string, map[string]bool) {
	t.Helper()
	values, _ := collectStoreValues(st, minLen, withHistory)
	repls := buildReplacements(values, mask)
	var buf bytes.Buffer
	hit := map[string]bool{}
	if err := redactReader(strings.NewReader(in), &buf, repls, hit); err != nil {
		t.Fatalf("redactReader: %v", err)
	}
	return buf.String(), hit
}

func TestRedactReplacesValues(t *testing.T) {
	st := redactStore()
	in := "token=supersecretvalue123 pw=hunter2hunter2pw ok\nnext supersecretvalue123 line\n"
	out, hit := redactText(t, st, in, 8, false, false)

	if strings.Contains(out, "supersecretvalue123") || strings.Contains(out, "hunter2hunter2pw") {
		t.Fatalf("значение утекло в вывод: %q", out)
	}
	if !strings.Contains(out, "[redacted:whois/API_TOKEN]") {
		t.Errorf("нет плейсхолдера токена: %q", out)
	}
	if !strings.Contains(out, "[redacted:db/PASSWORD@prod]") {
		t.Errorf("нет плейсхолдера с инстансом: %q", out)
	}
	if !hit["whois/API_TOKEN"] || !hit["db@prod/PASSWORD"] {
		t.Errorf("не отмечены найденные ключи: %v", hit)
	}
	// перенос строк сохраняется (два '\n' на входе — два на выходе)
	if strings.Count(out, "\n") != 2 {
		t.Errorf("переносы строк не сохранены: %q", out)
	}
}

func TestRedactShortValueSkipped(t *testing.T) {
	st := redactStore()
	// "abc" короче --min 8 → не должно ни трогаться, ни давать ложных срабатываний
	out, hit := redactText(t, st, "value is abc here\n", 8, false, false)
	if out != "value is abc here\n" {
		t.Errorf("короткое значение не должно чиститься: %q", out)
	}
	if len(hit) != 0 {
		t.Errorf("коротких срабатываний быть не должно: %v", hit)
	}
}

func TestRedactRefSkipped(t *testing.T) {
	// app/REFD — ссылка на whois/API_TOKEN: своё значение не хранит, поэтому
	// в вывод должно попасть имя родителя, а не REFD.
	st := redactStore()
	out, _ := redactText(t, st, "x=supersecretvalue123\n", 8, false, false)
	if strings.Contains(out, "app/REFD") {
		t.Errorf("ссылка не должна давать собственный плейсхолдер: %q", out)
	}
	if !strings.Contains(out, "[redacted:whois/API_TOKEN]") {
		t.Errorf("значение по ссылке должно чиститься под именем родителя: %q", out)
	}
}

func TestRedactLongestFirst(t *testing.T) {
	// значение, содержащее внутри другое сохранённое значение, должно замениться
	// целиком (длинные меняются первыми).
	st := &store.Store{Version: 1, Projects: map[string]map[string]store.Secret{
		"a": {"BASE": {Value: "abcdefgh"}, "LONG": {Value: "abcdefgh_and_more"}},
	}}
	out, _ := redactText(t, st, "v=abcdefgh_and_more\n", 8, false, false)
	if strings.Contains(out, "abcdefgh") {
		t.Fatalf("осталась часть значения: %q", out)
	}
	if !strings.Contains(out, "[redacted:a/LONG]") {
		t.Errorf("длинное значение должно замениться целиком: %q", out)
	}
}

func TestRedactMask(t *testing.T) {
	st := redactStore()
	out, _ := redactText(t, st, "t=supersecretvalue123\n", 8, false, true)
	if !strings.Contains(out, "[redacted]") || strings.Contains(out, "whois") {
		t.Errorf("--mask должен скрывать и имя ключа: %q", out)
	}
}

func TestRedactPassThrough(t *testing.T) {
	// нет совпадений — вывод идентичен вводу, включая отсутствие финального \n
	st := redactStore()
	out, hit := redactText(t, st, "nothing secret here", 8, false, false)
	if out != "nothing secret here" {
		t.Errorf("вывод должен совпадать со входом: %q", out)
	}
	if len(hit) != 0 {
		t.Errorf("срабатываний быть не должно: %v", hit)
	}
}

func TestRedactHistory(t *testing.T) {
	st := &store.Store{Version: 1, Projects: map[string]map[string]store.Secret{
		"a": {"TOK": {Value: "current-value-x", History: []store.Version{{Value: "old-leaked-value"}}}},
	}}
	// без --history старое значение не трогается
	out, _ := redactText(t, st, "leak=old-leaked-value\n", 8, false, false)
	if !strings.Contains(out, "old-leaked-value") {
		t.Errorf("без --history прошлое значение не чистится: %q", out)
	}
	// с --history — чистится под ~prev
	out, hit := redactText(t, st, "leak=old-leaked-value\n", 8, true, false)
	if strings.Contains(out, "old-leaked-value") {
		t.Fatalf("с --history прошлое значение должно чиститься: %q", out)
	}
	if !hit["a/TOK~prev"] {
		t.Errorf("не отмечено историческое значение: %v", hit)
	}
	if !strings.Contains(out, "~prev") {
		t.Errorf("плейсхолдер истории должен нести ~prev: %q", out)
	}
}
