package command

import (
	"bufio"
	"bytes"
	"database/sql"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kaidstor/sec/internal/backup"
	"github.com/kaidstor/sec/internal/store"
)

// secProcTo — как secProc, но stdout процесса — заданный файл (без
// промежуточного копирования: ребёнок пишет прямо в этот дескриптор).
func secProcTo(t *testing.T, out *os.File, stdin string, args ...string) secResult {
	t.Helper()
	cmd := secCmd(stdin, args...)
	var e bytes.Buffer
	cmd.Stdout, cmd.Stderr = out, &e
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode() // -1 — убит сигналом (SIGPIPE)
	} else if err != nil {
		t.Fatal(err)
	}
	return secResult{code: code, stderr: e.String()}
}

// brokenStdouts — stdout, запись в который не проходит: дескриптор только на
// чтение (EBADF) и пайп без читателя (EPIPE/SIGPIPE).
func brokenStdouts(t *testing.T) map[string]func() *os.File {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX-дескрипторы")
	}
	return map[string]func() *os.File{
		"readonly": func() *os.File {
			p := filepath.Join(t.TempDir(), "ro")
			os.WriteFile(p, nil, 0o600)
			f, err := os.Open(p)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { f.Close() })
			return f
		},
		"closed-pipe": func() *os.File {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			r.Close()
			t.Cleanup(func() { w.Close() })
			return w
		},
	}
}

func devNullOut(t *testing.T) *os.File {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX-дескрипторы")
	}
	f, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

// get --once в /dev/null (так выглядит и закрытый fd 1 — Go подставляет
// /dev/null) отказывает до удаления. Раньше: код 0, ключ удалён, значения нет.
func TestOnceRefusesDiscardedStdout(t *testing.T) {
	cliEnv(t)
	secProc(t, "once-value-1", "set", "app/K")
	for _, mode := range [][]string{nil, {"--json"}} {
		r := secProcTo(t, devNullOut(t), "", append([]string{"get", "app/K", "--once"}, mode...)...)
		// в JSON отказ — конвертом в тот же stdout, stderr пуст
		if r.code != 2 || (mode == nil && !strings.Contains(r.stderr, "ключ не тронут")) {
			t.Fatalf("%v: ожидался отказ до удаления: %+v", mode, r)
		}
		if g := secProc(t, "", "get", "app/K"); g.stdout != "once-value-1\n" {
			t.Fatalf("%v: ключ должен остаться: %+v", mode, g)
		}
	}
}

// get --once, чей вывод не дошёл (текст или JSON-конверт): ненулевой код и
// прямое «уже удалён». Раньше — код 0 (или смерть от SIGPIPE без слова).
func TestOnceOutputFailureIsReported(t *testing.T) {
	cliEnv(t)
	for name, open := range brokenStdouts(t) {
		for _, mode := range [][]string{nil, {"--json"}} {
			secProc(t, "once-value-2", "set", "app/K")
			r := secProcTo(t, open(), "", append([]string{"get", "app/K", "--once"}, mode...)...)
			if r.code != 2 || !strings.Contains(r.stderr, "app/K уже удалён") {
				t.Fatalf("%s %v: ошибка вывода должна дать код 2 и объяснение: %+v", name, mode, r)
			}
			if strings.Contains(r.stderr, "once-value-2") {
				t.Fatalf("%s %v: значение в stderr", name, mode)
			}
			if g := secProc(t, "", "get", "app/K"); g.code != 3 {
				t.Fatalf("%s %v: удаление уже зафиксировано, ожидался код 3: %+v", name, mode, g)
			}
		}
	}
}

var hexKeyRe = regexp.MustCompile(`[0-9a-f]{64}`)

type shortOutput struct{}

func (shortOutput) Write(p []byte) (int, error) { return len(p) / 2, nil }

func runShortOutput(t *testing.T, args ...string) int {
	t.Helper()
	old := realStdout
	realStdout = shortOutput{}
	t.Cleanup(func() { realStdout, stdout, jsonMode = old, old, false })
	return Run(args)
}

func TestOnceShortOutputIsReported(t *testing.T) {
	for _, mode := range [][]string{nil, {"--json"}} {
		t.Run(strings.Join(mode, ""), func(t *testing.T) {
			cliEnv(t)
			secProc(t, "once-short-output", "set", "app/K")
			if code := runShortOutput(t, append([]string{"get", "app/K", "--once"}, mode...)...); code != 2 {
				t.Fatalf("короткая запись: код %d, ожидался 2", code)
			}
			if g := secProc(t, "", "get", "app/K"); g.code != 3 {
				t.Fatalf("удаление должно остаться зафиксировано: код %d", g.code)
			}
		})
	}
}

func TestRekeyEnvShortOutputKeepsSlot(t *testing.T) {
	cliEnv(t)
	secProc(t, "rekey-short-output", "set", "app/K")
	if code := runShortOutput(t, "rekey"); code != 2 {
		t.Fatalf("короткая запись: код %d, ожидался 2", code)
	}
	if _, err := os.Stat(store.PendingKeyPath()); err != nil {
		t.Fatal("recovery-ключ должен остаться в слоте")
	}
	if g := secProc(t, "", "get", "app/K"); g.stdout != "rekey-short-output\n" {
		t.Fatalf("стор должен открываться с recovery-ключом: код %d", g.code)
	}
}

func TestFinishOutputErrors(t *testing.T) {
	for name, data := range map[string]any{"short-write": "value", "encode": make(chan int)} {
		t.Run(name, func(t *testing.T) {
			old := realStdout
			realStdout = shortOutput{}
			defer func() { realStdout, stdout, jsonMode = old, old, false }()
			startOutput("get", true)
			emit(data)
			if code := finish(0); code != 2 {
				t.Fatalf("ошибка JSON-вывода: код %d, ожидался 2", code)
			}
		})
	}
}

// env-rekey в /dev/null не начинается: новый ключ некуда напечатать.
func TestRekeyEnvRefusesDiscardedStdout(t *testing.T) {
	cliEnv(t)
	secProc(t, "tok-123456789", "set", "app/TOKEN")
	r := secProcTo(t, devNullOut(t), "", "rekey")
	if r.code != 2 || !strings.Contains(r.stderr, "ротация не начата") {
		t.Fatalf("ожидался отказ до ротации: код %d, %s", r.code, r.stderr)
	}
	if g := secProc(t, "", "get", "app/TOKEN"); g.stdout != "tok-123456789\n" {
		t.Fatalf("стор должен открываться прежним ключом: код %d", g.code)
	}
	if _, err := os.Stat(store.PendingKeyPath()); !os.IsNotExist(err) {
		t.Fatal("слот не должен появляться")
	}
}

// env-rekey, чей ключ не дошёл до stdout: код 2, слот — единственная копия
// нового ключа — остаётся, стор открывается. Раньше слот удалялся после
// «успешной» печати, и стор терялся.
func TestRekeyEnvOutputFailureKeepsSlot(t *testing.T) {
	for name, open := range brokenStdouts(t) {
		t.Run(name, func(t *testing.T) {
			cliEnv(t)
			secProc(t, "tok-123456789", "set", "app/TOKEN")
			r := secProcTo(t, open(), "", "rekey")
			if r.code != 2 || !strings.Contains(r.stderr, store.PendingKeyPath()) {
				t.Fatalf("ожидался код 2 и путь слота: код %d", r.code)
			}
			if hexKeyRe.MatchString(r.stderr) {
				t.Fatal("ключ попал в stderr")
			}
			slot, err := os.ReadFile(store.PendingKeyPath())
			if err != nil {
				t.Fatal("слот нового ключа должен остаться")
			}
			if g := secProc(t, "", "get", "app/TOKEN"); g.stdout != "tok-123456789\n" {
				t.Fatalf("старый SEC_KEY + слот: код %d", g.code)
			}
			t.Setenv("SEC_KEY", strings.TrimSpace(string(slot)))
			if g := secProc(t, "", "get", "app/TOKEN"); g.stdout != "tok-123456789\n" {
				t.Fatalf("ключ из слота: код %d", g.code)
			}
		})
	}
}

func TestRekeyEnvJSONRefusedBeforeMutation(t *testing.T) {
	cliEnv(t)
	secProc(t, "rekey-json-value", "set", "app/K")
	r := secProc(t, "", "rekey", "--json")
	env := decodeEnvelope(t, r.stdout)
	if r.code != 2 || env["error"].(map[string]any)["kind"] != kindUsage || hexKeyRe.MatchString(r.stdout+r.stderr) {
		t.Fatal("env rekey --json должен отказать до ротации без раскрытия ключа")
	}
	for _, open := range brokenStdouts(t) {
		if r := secProcTo(t, open(), "", "rekey", "--json"); r.code != 2 {
			t.Fatalf("ошибка вывода JSON-отказа: код %d, ожидался 2", r.code)
		}
	}
	if _, err := os.Stat(store.PendingKeyPath()); !os.IsNotExist(err) {
		t.Fatal("отказ JSON не должен создавать recovery-слот")
	}
	if g := secProc(t, "", "get", "app/K"); g.stdout != "rekey-json-value\n" {
		t.Fatalf("стор должен открываться прежним ключом: код %d", g.code)
	}
}

func TestClosedStdoutRefusesBeforeMutation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("закрытие POSIX fd 1 перед exec")
	}
	for _, args := range [][]string{{"get", "app/K", "--once"}, {"get", "app/K", "--once", "--json"}, {"rekey"}, {"rekey", "--json"}} {
		t.Run(strings.Join(args, "-"), func(t *testing.T) {
			cliEnv(t)
			secProc(t, "closed-fd-value", "set", "app/K")
			child := secCmd("", args...)
			cmd := exec.Command("/bin/sh", append([]string{"-c", `exec "$@" >&-`, "closed-stdout", child.Path}, child.Args[1:]...)...)
			cmd.Env, cmd.Stdin = child.Env, child.Stdin
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err, ok := cmd.Run().(*exec.ExitError); !ok || err.ExitCode() != 2 {
				t.Fatalf("закрытый fd 1 должен дать код 2: %v", err)
			}
			if g := secProc(t, "", "get", "app/K"); g.stdout != "closed-fd-value\n" {
				t.Fatalf("стор не должен изменяться: код %d", g.code)
			}
			if hexKeyRe.MatchString(stderr.String()) {
				t.Fatal("мастер-ключ попал в stderr")
			}
		})
	}
}

func sealArchive(t *testing.T, dir, body string) string {
	t.Helper()
	blob, err := backup.Seal([]byte(body), os.Getenv("SEC_PASSPHRASE"))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "bak.enc")
	if err := os.WriteFile(p, blob, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// restore --replace архива без value (здесь — с чужой «локальной» ссылкой)
// отказывает и не трогает стор; раньше ключ становился пустой строкой.
// Архив в форме, которую всегда писал sec (value:"" у ссылки, история),
// восстанавливается как прежде.
func TestRestoreReplaceRefusesValuelessArchive(t *testing.T) {
	dir := cliEnv(t)
	t.Setenv("SEC_PASSPHRASE", "synthetic-passphrase-123")
	secProc(t, "SYNTHETIC-ORIGINAL", "set", "app/K")

	for _, body := range []string{
		`{"version":2,"projects":{"app":{"K":{"payloadRef":"local-only-id"}}}}`,
		`{"version":2,"projects":{"app":{"K":{"value":null}}}}`,
		`{"version":2,"projects":{"app":{"K":{"value":"","payloadRef":"local-only-id"}}}}`,
		`{"version":2,"projects":{"app":{"K":{"value":"x","history":[{}]}}}}`,
		`{"version":2,"projects":{"app":{"K":{"value":"x","redo":[{"value":null}]}}}}`,
	} {
		bad := sealArchive(t, dir, body)
		if r := secProc(t, "", "restore", "--file", bad, "--replace"); r.code != 2 {
			t.Fatalf("некорректный архив должен отвергаться: код %d", r.code)
		}
		if g := secProc(t, "", "get", "app/K"); g.stdout != "SYNTHETIC-ORIGINAL\n" {
			t.Fatalf("прежний стор должен остаться: код %d", g.code)
		}
	}

	good := sealArchive(t, dir, `{"version":2,"projects":{`+
		`"base":{"X":{"value":"bx-1","updatedAt":"2026-01-02T00:00:00Z","history":[{"value":"bx-0","updatedAt":"2026-01-01T00:00:00Z"}]}},`+
		`"app":{"L":{"value":"","ref":"base/X","updatedAt":"2026-01-03T00:00:00Z"},"E":{"value":"","updatedAt":"2026-01-04T00:00:00Z"}}}}`)
	if r := secProc(t, "", "restore", "--file", good, "--replace"); r.code != 0 {
		t.Fatalf("совместимый архив: %+v", r)
	}
	if g := secProc(t, "", "get", "app/L"); g.stdout != "bx-1\n" {
		t.Errorf("ссылка: %+v", g)
	}
	if g := secProc(t, "", "get", "base/X", "--prev", "1"); g.stdout != "bx-0\n" {
		t.Errorf("история: %+v", g)
	}
	if g := secProc(t, "", "get", "app/E"); g.code != 0 || g.stdout != "\n" {
		t.Errorf("пустое значение: %+v", g)
	}
}

// scan/redact закрывают снимок до чтения stdin: пока они ждут ввода, WAL
// после чужих записей сжимается (раньше checkpoint отвечал busy).
func TestReadSnapshotClosedBeforeInput(t *testing.T) {
	for _, args := range [][]string{
		{"redact", "--store-only", "--min", "1000"},
		{"scan", "-"},
	} {
		t.Run(args[0], func(t *testing.T) {
			cliEnv(t)
			secProc(t, "snapshot-long-value-1", "set", "app/LONG")
			secProc(t, "abc", "set", "app/SHORT")

			cmd := secCmd("", args...)
			cmd.Stdin = nil
			stdin, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			stderr, err := cmd.StderrPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer cmd.Wait()
			defer stdin.Close()
			// предупреждение о пропущенных коротких печатается после сбора значений
			seen := make(chan bool, 1)
			go func() {
				sc := bufio.NewScanner(stderr)
				for sc.Scan() {
					if strings.Contains(sc.Text(), "пропущено") {
						seen <- true
						break
					}
				}
				close(seen)
				for sc.Scan() {
				}
			}()
			select {
			case ok := <-seen:
				if !ok {
					t.Fatal("процесс завершился до ожидания stdin")
				}
			case <-time.After(20 * time.Second):
				t.Fatal("нет предупреждения о сборе значений")
			}
			for i := 0; i < 3; i++ {
				if r := secProc(t, "next-value-123", "set", "app/W"); r.code != 0 {
					t.Fatalf("set: %+v", r)
				}
			}
			db, err := sql.Open("sqlite", "file:"+os.Getenv("SEC_STORE")+"?mode=rw")
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var busy, logN, ckpt int
			if err := db.QueryRow("PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &logN, &ckpt); err != nil {
				t.Fatal(err)
			}
			if busy != 0 {
				t.Fatalf("%s держит снимок, пока ждёт stdin: checkpoint busy=%d log=%d", args[0], busy, logN)
			}
		})
	}
}
