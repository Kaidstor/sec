package command

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSplitRemoteTarget(t *testing.T) {
	cases := []struct {
		in, host, path string
		ok             bool
	}{
		{"recon:/app/.env", "recon", "/app/.env", true},
		{"user@host:rel/path", "user@host", "rel/path", true},
		{"host:", "host", "", true}, // пустой путь — ошибку даст sshWriteFile
		{"./local:file", "", "", false},
		{`C:\Users\x`, "", "", false}, // диск Windows
		{"c:/x", "", "", false},
		{"/abs/path", "", "", false},
		{".env", "", "", false},
		{":path", "", "", false},
		{"dir/host:path", "", "", false}, // слэш до ':' — локальный путь
	}
	for _, c := range cases {
		host, path, ok := splitRemoteTarget(c.in)
		if host != c.host || path != c.path || ok != c.ok {
			t.Errorf("splitRemoteTarget(%q) = (%q, %q, %v), ожидалось (%q, %q, %v)",
				c.in, host, path, ok, c.host, c.path, c.ok)
		}
	}
}

func TestShSingleQuote(t *testing.T) {
	if got := shSingleQuote("/tmp/x y'z"); got != `'/tmp/x y'\''z'` {
		t.Errorf("shSingleQuote: %s", got)
	}
}

// sshWriteFile проверяем фейковым ssh в PATH: он записывает argv и stdin —
// значение обязано прийти через stdin, путь — заэкранированным в команде.
func TestSSHWriteFileViaFakeSSH(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("фейковый ssh — sh-скрипт")
	}
	dir := t.TempDir()
	out := filepath.Join(dir, "out.bin")
	argsFile := filepath.Join(dir, "args.txt")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"" + argsFile + "\"\ncat > \"" + out + "\"\n"
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	if err := sshWriteFile("myhost", "/app/x y'z.env", []byte("secret-bytes")); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(out); string(data) != "secret-bytes" {
		t.Errorf("stdin до ssh не дошёл: %q", data)
	}
	args := string(mustRead(t, argsFile))
	if !strings.Contains(args, "myhost") {
		t.Errorf("нет хоста в argv: %s", args)
	}
	if !strings.Contains(args, `'/app/x y'\''z.env'`) {
		t.Errorf("путь не заэкранирован в команде: %s", args)
	}
	if strings.Contains(args, "secret-bytes") {
		t.Errorf("значение попало в argv: %s", args)
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
