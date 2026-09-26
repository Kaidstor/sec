package command

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kaidstor/sec/internal/store"
)

func TestSplitGlobalFlags(t *testing.T) {
	cases := []struct {
		in, want string
		json     bool
	}{
		{"ls --json", "ls", true},
		{"--json get a/B --peek", "get a/B --peek", true},
		{"get a/B", "get a/B", false},
		{"ls --json --human", "ls", false},
		{"run app -- tool --json", "run app -- tool --json", false}, // после -- — чужие аргументы
		{"run app --json -- tool", "run app -- tool", true},
	}
	for _, c := range cases {
		gotJSON, got := splitGlobalFlags(strings.Fields(c.in))
		if gotJSON != c.json || strings.Join(got, " ") != c.want {
			t.Errorf("splitGlobalFlags(%q) = %v, %q; ожидалось %v, %q", c.in, gotJSON, strings.Join(got, " "), c.json, c.want)
		}
	}
}

// testStore заводит стор во временном каталоге с мастер-ключом из SEC_KEY и
// одним ключом demo/TOKEN.
func testStore(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("SEC_STORE", filepath.Join(dir, "store.enc"))
	t.Setenv("SEC_KEY", strings.Repeat("ab", 32))
	t.Setenv("SEC_NO_USAGE", "1")
	st, key, _, err := store.Open(true)
	if err != nil {
		t.Fatal(err)
	}
	store.Put(st.Project("demo"), "TOKEN", "tok-value-123456")
	if err := store.Save(st, key); err != nil {
		t.Fatal(err)
	}
}

// runCLI прогоняет Run и возвращает код и настоящий stdout.
func runCLI(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var buf bytes.Buffer
	old := realStdout
	realStdout = &buf
	defer func() { realStdout, stdout, jsonMode = old, old, false }()
	code := Run(args)
	return code, buf.String()
}

func decodeEnvelope(t *testing.T, out string) map[string]any {
	t.Helper()
	var env map[string]any
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("stdout — не JSON: %v\n%s", err, out)
	}
	for _, k := range []string{"v", "command", "exit", "data", "error"} {
		if _, ok := env[k]; !ok {
			t.Errorf("в конверте нет поля %q: %s", k, out)
		}
	}
	return env
}

// Обёртки (config.go соседних CLI, скрипты) читают сырой stdout `sec get`
// без флагов — там должно быть чистое значение и ничего больше.
func TestGetPlainStdoutIsBareValue(t *testing.T) {
	testStore(t)
	code, out := runCLI(t, "get", "demo/TOKEN")
	if code != 0 || out != "tok-value-123456\n" {
		t.Errorf("get без флагов: код %d, stdout %q", code, out)
	}
}

func TestGetJSONEnvelope(t *testing.T) {
	testStore(t)
	code, out := runCLI(t, "get", "demo/TOKEN", "--json")
	env := decodeEnvelope(t, out)
	data, _ := env["data"].(map[string]any)
	if code != 0 || env["exit"] != float64(0) || env["command"] != "get" || env["error"] != nil {
		t.Errorf("конверт get: код %d, %s", code, out)
	}
	if data["value"] != "tok-value-123456" || data["ref"] != "demo/TOKEN" {
		t.Errorf("data get: %v", data)
	}

	_, out = runCLI(t, "--json", "get", "demo/TOKEN", "--peek")
	if strings.Contains(out, "tok-value-123456") {
		t.Errorf("--peek отдал значение в JSON: %s", out)
	}
	data, _ = decodeEnvelope(t, out)["data"].(map[string]any)
	if data["mask"] == nil || data["chars"] != float64(16) {
		t.Errorf("data --peek: %v", data)
	}
}

// Команды, у которых --json был и до конверта: прежний ответ — в data как есть.
func TestLsJSONKeepsPayloadInData(t *testing.T) {
	testStore(t)
	_, out := runCLI(t, "ls", "--json")
	data, ok := decodeEnvelope(t, out)["data"].(map[string]any)
	if !ok || data["demo"] == nil {
		t.Fatalf("ls --json: ожидалась карта проектов в data: %s", out)
	}
	if strings.Contains(out, "tok-value-123456") {
		t.Errorf("ls --json отдал значение: %s", out)
	}
}

func TestJSONFailureIsEnvelope(t *testing.T) {
	testStore(t)
	code, out := runCLI(t, "frobnicate", "--json")
	env := decodeEnvelope(t, out)
	errObj, _ := env["error"].(map[string]any)
	if code != 2 || env["exit"] != float64(2) || errObj["kind"] != kindUsage || errObj["message"] == "" {
		t.Errorf("неизвестная команда в --json: код %d, %s", code, out)
	}

	code, out = runCLI(t, "run", "demo", "--json", "--", "true")
	errObj, _ = decodeEnvelope(t, out)["error"].(map[string]any)
	if code != 2 || errObj["kind"] != kindUsage {
		t.Errorf("run --json должен отказать конвертом: код %d, %s", code, out)
	}
}

// Команда без явных данных всё равно отдаёт конверт — текст уходит в data.text.
func TestFinishFallsBackToText(t *testing.T) {
	var buf bytes.Buffer
	old := realStdout
	realStdout = &buf
	defer func() { realStdout, stdout, jsonMode = old, old, false }()
	startOutput("demo", true)
	stdout.Write([]byte("строка\n"))
	warnf("осторожно")
	finish(0)
	env := decodeEnvelope(t, buf.String())
	data, _ := env["data"].(map[string]any)
	warn, _ := env["warning"].([]any)
	if data["text"] != "строка" || len(warn) != 1 {
		t.Errorf("fallback: %s", buf.String())
	}
}
