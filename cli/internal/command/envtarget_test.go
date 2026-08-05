package command

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestParseEnvTarget(t *testing.T) {
	cases := []struct {
		in, host, path string
		bad            bool
	}{
		{in: "whois:/app/.env.whois", host: "whois", path: "/app/.env.whois"},
		{in: "user@host:rel/.env", host: "user@host", path: "rel/.env"},
		{in: "./.env", path: "./.env"},
		{in: "/abs/.env", path: "/abs/.env"},
		{in: "host:", bad: true},
		{in: "", bad: true},
	}
	for _, c := range cases {
		got, err := parseEnvTarget(c.in)
		if c.bad {
			if err == nil {
				t.Errorf("parseEnvTarget(%q): ожидалась ошибка", c.in)
			}
			continue
		}
		if err != nil || got.host != c.host || got.path != c.path {
			t.Errorf("parseEnvTarget(%q) = %+v, %v; ожидалось {%q %q}", c.in, got, err, c.host, c.path)
		}
	}
}

// Второй позиционный у sec diff — либо env-файл, либо имя проекта/инстанса.
func TestLooksLikeEnvTarget(t *testing.T) {
	yes := []string{"whois:/app/.env", "./.env", "../conf/.env", "/etc/app.env", "~/x.env"}
	no := []string{"whois", "commercial", "some-bot"}
	for _, s := range yes {
		if !looksLikeEnvTarget(s) {
			t.Errorf("%q должен считаться env-файлом", s)
		}
	}
	for _, s := range no {
		if looksLikeEnvTarget(s) {
			t.Errorf("%q — имя проекта/инстанса, не файл", s)
		}
	}
}

// Локальная цель: чтение отсутствующего файла — не ошибка, а запись не трогает
// права существующего (прод-конфиг читает демон под своим пользователем).
func TestEnvTargetLocalReadWriteKeepsMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX-права")
	}
	path := filepath.Join(t.TempDir(), ".env")
	tgt := envTarget{path: path}

	if _, exists, err := tgt.read(false); err != nil || exists {
		t.Fatalf("отсутствующий файл: exists=%v, err=%v", exists, err)
	}
	if err := os.WriteFile(path, []byte("A=1\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	data, exists, err := tgt.read(false)
	if err != nil || !exists || string(data) != "A=1\n" {
		t.Fatalf("чтение: %q, exists=%v, err=%v", data, exists, err)
	}
	if err := tgt.write(false, []byte("A=2\n")); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o640 {
		t.Errorf("права изменились: %o", fi.Mode().Perm())
	}
	if data, _, _ := tgt.read(false); string(data) != "A=2\n" {
		t.Errorf("запись не применилась: %q", data)
	}
}

// fakeSSH подменяет ssh скриптом, который пишет argv в файл и выполняет
// удалённую команду локально — так проверяется и протокол чтения, и то, что
// значения уходят через stdin, а не в argv.
func fakeSSH(t *testing.T) (argsFile string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("фейковый ssh — sh-скрипт")
	}
	dir := t.TempDir()
	argsFile = filepath.Join(dir, "args.txt")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"" + argsFile + "\"\nshift 2\nsh -c \"$1\"\n"
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return argsFile
}

func TestEnvTargetRemoteRoundTrip(t *testing.T) {
	argsFile := fakeSSH(t)
	path := filepath.Join(t.TempDir(), ".env with space")
	tgt := envTarget{host: "whois", path: path}

	if _, exists, err := tgt.read(false); err != nil || exists {
		t.Fatalf("отсутствующий файл на хосте: exists=%v, err=%v", exists, err)
	}
	if err := tgt.write(false, []byte("TOKEN=supersecretvalue\n")); err != nil {
		t.Fatal(err)
	}
	args := string(mustRead(t, argsFile))
	if strings.Contains(args, "supersecretvalue") {
		t.Errorf("значение попало в argv: %s", args)
	}
	if !strings.Contains(args, shSingleQuote(path)) {
		t.Errorf("путь не заэкранирован: %s", args)
	}

	data, exists, err := tgt.read(false)
	if err != nil || !exists || string(data) != "TOKEN=supersecretvalue\n" {
		t.Fatalf("чтение с хоста: %q, exists=%v, err=%v", data, exists, err)
	}

	bak := path + ".bak-test"
	if err := tgt.backup(false, bak); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(bak); string(b) != "TOKEN=supersecretvalue\n" {
		t.Errorf("бэкап не совпал: %q", b)
	}
}

func TestSudoWrapAndPasswordDetection(t *testing.T) {
	if got := sudoWrap("cat > /app/.env", false); got != "cat > /app/.env" {
		t.Errorf("без --sudo команда не оборачивается: %q", got)
	}
	got := sudoWrap("cat > /app/.env", true)
	if !strings.HasPrefix(got, "sudo -n sh -c ") || !strings.Contains(got, `'cat > /app/.env'`) {
		t.Errorf("sudoWrap: %q", got)
	}
	for _, s := range []string{
		"sudo: a password is required",
		"sudo: no tty present and no askpass program specified",
		"sudo: для выполнения требуется пароль",
	} {
		if !sudoNeedsPassword(s) {
			t.Errorf("не распознан отказ по паролю: %q", s)
		}
	}
	if sudoNeedsPassword("user is not in the sudoers file") {
		t.Error("отказ по правам не должен уходить в интерактивный прогрев")
	}
}
