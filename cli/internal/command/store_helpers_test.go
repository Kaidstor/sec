package command

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/kaidstor/sec/internal/store"
)

func TestEditBlock(t *testing.T) {
	st := &store.Store{Version: 1, Projects: map[string]map[string]store.Secret{
		"app":  {"OWN": {Value: "v"}, "R": {Ref: "base/X"}},
		"base": {"X": {Value: "base-x"}},
	}, Extends: map[string][]string{"app": {"base"}}}

	if msg := editBlock(st, "app", "OWN"); msg != "" {
		t.Errorf("собственное значение должно быть редактируемым, got %q", msg)
	}
	if msg := editBlock(st, "app", "NEW"); msg != "" {
		t.Errorf("новый ключ должен быть редактируемым, got %q", msg)
	}
	if msg := editBlock(st, "app", "R"); msg == "" {
		t.Error("ссылку нельзя редактировать напрямую — ждали блокировку")
	}
	if msg := editBlock(st, "app", "X"); msg == "" {
		t.Error("унаследованный ключ нельзя редактировать напрямую — ждали блокировку")
	}
}

// writeFile0600 обязан дожимать права и у существующего файла: os.WriteFile
// применяет mode только при создании, файл с 0644 остался бы читаемым всем.
func TestWriteFile0600TightensExisting(t *testing.T) {
	p := filepath.Join(t.TempDir(), "out.env")
	if err := os.WriteFile(p, []byte("старое"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeFile0600(p, []byte("секрет")); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("права %v, ожидалось 0600", fi.Mode().Perm())
	}
	b, _ := os.ReadFile(p)
	if string(b) != "секрет" {
		t.Errorf("содержимое %q", b)
	}
}
