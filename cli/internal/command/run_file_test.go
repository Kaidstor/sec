package command

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/kaidstor/sec/internal/store"
)

func TestParseFileMount(t *testing.T) {
	cases := []struct {
		spec string
		want fileMount
	}{
		{"CERT", fileMount{envName: "CERT", proj: "run-proj", key: "CERT"}},
		{"tauri-keys/APP_PEM", fileMount{envName: "APP_PEM", proj: "tauri-keys", key: "APP_PEM"}},
		{"SIGN_KEY=tauri-keys/APP_PEM", fileMount{envName: "SIGN_KEY", proj: "tauri-keys", key: "APP_PEM"}},
		{"CERT:/tmp/x.pem", fileMount{envName: "CERT", proj: "run-proj", key: "CERT", dest: "/tmp/x.pem"}},
		{"K=p/A:./out/x=y.pem", fileMount{envName: "K", proj: "p", key: "A", dest: "./out/x=y.pem"}},
		// двоеточие диска Windows — часть пути, а не второй разделитель
		{`CERT:C:\tmp\x.pem`, fileMount{envName: "CERT", proj: "run-proj", key: "CERT", dest: `C:\tmp\x.pem`}},
	}
	for _, c := range cases {
		got, err := parseFileMount(c.spec, "run-proj")
		if err != nil {
			t.Errorf("parseFileMount(%q): %v", c.spec, err)
			continue
		}
		if got != c.want {
			t.Errorf("parseFileMount(%q) = %+v, ожидалось %+v", c.spec, got, c.want)
		}
	}
	for _, bad := range []string{"", ":x", "CERT:", "=p/K", "p/", "/K", "p/K/x", "п/K", "p/к"} {
		if _, err := parseFileMount(bad, "run-proj"); err == nil {
			t.Errorf("parseFileMount(%q): ожидалась ошибка", bad)
		}
	}
}

// Дубль env-имени — не «последний победил», а ошибка: молча подсунуть команде
// не тот файл хуже отказа.
func TestParseFileMountsDupEnv(t *testing.T) {
	if _, err := parseFileMounts([]string{"a/CERT", "b/CERT"}, "run-proj"); err == nil {
		t.Error("одинаковое env-имя из двух ссылок должно быть ошибкой")
	}
	got, err := parseFileMounts([]string{"a/CERT", "B=b/CERT"}, "run-proj")
	if err != nil || len(got) != 2 {
		t.Errorf("разведённые через ENV= имена должны проходить: %v, %v", got, err)
	}
}

func TestMaterializeMounts(t *testing.T) {
	bin := []byte{0x01, 0x00, 0xFF, 0x42}
	st := &store.Store{Projects: map[string]map[string]store.Secret{
		"keys": {
			"PEM": {Value: "pem-text", Meta: &store.Meta{Kind: "file", Filename: "app.pem"}},
			"P12": {Value: base64.StdEncoding.EncodeToString(bin), Enc: store.EncB64},
		},
	}}

	mounts, err := parseFileMounts([]string{"keys/PEM", "STORE=keys/P12"}, "keys")
	if err != nil {
		t.Fatal(err)
	}
	env, cleanup, err := materializeMounts(st, mounts)
	if err != nil {
		t.Fatal(err)
	}

	// текстовый — под исходным именем из меты, байт-в-байт
	pemPath := env["PEM"]
	if filepath.Base(pemPath) != "app.pem" {
		t.Errorf("имя файла должно браться из меты: %s", pemPath)
	}
	if b, _ := os.ReadFile(pemPath); string(b) != "pem-text" {
		t.Errorf("содержимое PEM: %q", b)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(pemPath); fi.Mode().Perm() != 0o600 {
			t.Errorf("права %v, ожидалось 0600", fi.Mode().Perm())
		}
	}
	// бинарный — декодированные байты, env-имя из ENV=
	if b, _ := os.ReadFile(env["STORE"]); string(b) != string(bin) {
		t.Errorf("бинарные байты не совпали: %v", b)
	}

	cleanup()
	for _, p := range []string{pemPath, env["STORE"]} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("после cleanup файл должен исчезнуть: %s", p)
		}
		if _, err := os.Stat(filepath.Dir(p)); !os.IsNotExist(err) {
			t.Errorf("временный каталог должен исчезнуть: %s", filepath.Dir(p))
		}
	}
}

func TestMaterializeMountsExplicitDest(t *testing.T) {
	st := &store.Store{Projects: map[string]map[string]store.Secret{
		"keys": {"PEM": {Value: "x"}},
	}}
	dest := filepath.Join(t.TempDir(), "my.pem")
	mounts, _ := parseFileMounts([]string{"keys/PEM:" + dest}, "keys")
	env, cleanup, err := materializeMounts(st, mounts)
	if err != nil {
		t.Fatal(err)
	}
	if env["PEM"] != dest {
		t.Errorf("env = %q, ожидался явный путь %q", env["PEM"], dest)
	}
	cleanup()
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Error("явный путь тоже должен удаляться по cleanup")
	}

	// существующий файл — отказ, содержимое не тронуто, ранее созданное прибрано
	if err := os.WriteFile(dest, []byte("чужое"), 0o644); err != nil {
		t.Fatal(err)
	}
	mounts, _ = parseFileMounts([]string{"OTHER=keys/PEM", "keys/PEM:" + dest}, "keys")
	if _, _, err := materializeMounts(st, mounts); err == nil || !strings.Contains(err.Error(), "существует") {
		t.Errorf("по существующему пути писать нельзя: %v", err)
	}
	if b, _ := os.ReadFile(dest); string(b) != "чужое" {
		t.Errorf("существующий файл повреждён: %q", b)
	}
}

func TestMaterializeMountsMissingKey(t *testing.T) {
	st := &store.Store{Projects: map[string]map[string]store.Secret{}}
	mounts, _ := parseFileMounts([]string{"keys/NOPE"}, "keys")
	if _, _, err := materializeMounts(st, mounts); err == nil {
		t.Error("несуществующий ключ должен быть ошибкой")
	}
}
