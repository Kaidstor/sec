package command

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/kaidstor/sec/internal/store"
)

func envDiffFixture() (map[string]store.Secret, map[string]string) {
	keys := map[string]store.Secret{
		"WHOXY_API_KEY":           {Value: "same-secret-value"},
		"WHOIS_HISTORY_PROVIDERS": {Value: "whoxy", Meta: &store.Meta{Kind: store.KindConfig}},
		"REDIS_URL":               {Value: "redis://store-only"},
	}
	file := map[string]string{
		"WHOXY_API_KEY":           "same-secret-value",
		"WHOIS_HISTORY_PROVIDERS": "whoxy,ripe",
		"DOMAINATOR_DB_URL":       "postgres://host-only-creds",
	}
	return keys, file
}

func TestCompareEnvFile(t *testing.T) {
	keys, file := envDiffFixture()
	got := map[string]envStatus{}
	for _, e := range compareEnvFile(keys, file, []byte("test-master-key")) {
		got[e.key] = e.status
	}
	want := map[string]envStatus{
		"WHOXY_API_KEY":           envSame,
		"WHOIS_HISTORY_PROVIDERS": envDiffer,
		"REDIS_URL":               envMissing,
		"DOMAINATOR_DB_URL":       envExtra,
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s: статус %v, ожидался %v", k, got[k], w)
		}
	}
}

// В вывод попадают имена и статусы; значения — только у kind: config. Секрет,
// который есть на обеих сторонах или только на хосте, раскрываться не должен.
func TestPrintEnvDiffLeaksOnlyConfigValues(t *testing.T) {
	keys, file := envDiffFixture()
	entries := compareEnvFile(keys, file, []byte("test-master-key"))

	var c envCounts
	out := captureStdout(t, func() { c = printEnvDiff(entries, envTarget{host: "whois", path: "/app/.env"}, false) })

	for _, secret := range []string{"same-secret-value", "redis://store-only", "postgres://host-only-creds"} {
		if strings.Contains(out, secret) {
			t.Errorf("значение секрета утекло в вывод: %q\n%s", secret, out)
		}
	}
	if !strings.Contains(out, "стор: whoxy") || !strings.Contains(out, "файл: whoxy,ripe") {
		t.Errorf("значения kind: config должны показываться открыто:\n%s", out)
	}
	if c != (envCounts{same: 1, differ: 1, missing: 1, extra: 1}) {
		t.Errorf("счётчики: %+v", c)
	}
	if !c.changed() {
		t.Error("расхождение должно считаться изменением")
	}
	if !strings.Contains(out, "? DOMAINATOR_DB_URL") {
		t.Errorf("ключ только на хосте помечается '?':\n%s", out)
	}
}

// --replace меняет смысл ключей, которых нет в сторе: они не остаются, а гибнут.
func TestPrintEnvDiffReplaceMarksDeletions(t *testing.T) {
	keys, file := envDiffFixture()
	entries := compareEnvFile(keys, file, []byte("test-master-key"))
	out := captureStdout(t, func() { printEnvDiff(entries, envTarget{path: "./.env"}, true) })

	if !strings.Contains(out, "- DOMAINATOR_DB_URL") || !strings.Contains(out, "будет удалён") {
		t.Errorf("--replace должен показывать удаляемые ключи:\n%s", out)
	}
	if !strings.Contains(out, "нет в файле") {
		t.Errorf("для локальной цели говорим «в файле», а не «на хосте»:\n%s", out)
	}
}

func TestOneLine(t *testing.T) {
	if got := oneLine("a\nb\tc"); got != `a\nb\tc` {
		t.Errorf("переносы должны экранироваться: %q", got)
	}
	if got := oneLine(strings.Repeat("x", 100)); len([]rune(got)) != 61 {
		t.Errorf("длинное значение должно обрезаться: %d символов", len([]rune(got)))
	}
}

// captureStdout перехватывает то, что команда печатает в os.Stdout.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = old }()

	done := make(chan string, 1)
	go func() {
		data, _ := io.ReadAll(r)
		done <- string(data)
	}()
	fn()
	w.Close()
	return <-done
}

// Значение конфига приезжает из чужого файла на хосте: сырой ESC в терминале —
// это уже не «показали настройку», а исполнили чужую escape-последовательность.
func TestOneLineEscapesControlChars(t *testing.T) {
	got := oneLine("val\x1b]52;c;cGF5bG9hZA==\x07end")
	if strings.ContainsAny(got, "\x1b\x07") {
		t.Errorf("управляющие символы прошли в терминал: %q", got)
	}
	if !strings.Contains(got, `\x1b`) || !strings.Contains(got, `\x07`) {
		t.Errorf("управляющие символы должны быть видны экранированными: %q", got)
	}
}
