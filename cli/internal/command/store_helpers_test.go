package command

import (
	"encoding/base64"
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

// Meta.Filename мог приехать из чужого стора (sync/restore) с разделителями
// любой ОС — в путь get --out он входит только простым именем, без traversal.
func TestSafeBaseName(t *testing.T) {
	cases := map[string]string{
		"server.p12":                 "server.p12",
		"../../.ssh/authorized_keys": "authorized_keys",
		`..\..\AppData\evil.exe`:     "evil.exe",
		`mixed/..\odd/name.txt`:      "name.txt",
		"..":                         "",
		".":                          "",
		"":                           "",
		"dir/":                       "",
	}
	for in, want := range cases {
		if got := safeBaseName(in); got != want {
			t.Errorf("safeBaseName(%q) = %q, ожидалось %q", in, got, want)
		}
	}
}

func TestDecodedB64Len(t *testing.T) {
	for n := 0; n <= 12; n++ {
		enc := base64.StdEncoding.EncodeToString(make([]byte, n))
		if got := decodedB64Len(enc); got != n {
			t.Errorf("decodedB64Len(len=%d) = %d, ожидалось %d", len(enc), got, n)
		}
	}
}

// Перезапись файлового секрета текстом обязана снять файловую метку: иначе
// get --out положит новый токен под именем старого сертификата.
func TestClearFileMeta(t *testing.T) {
	keys := map[string]store.Secret{
		"A": {Value: "v", Meta: &store.Meta{Kind: "file", Filename: "a.p12"}},
		"B": {Value: "v", Meta: &store.Meta{Kind: "file", Filename: "b.pem", Note: "note"}},
		"C": {Value: "v", Meta: &store.Meta{Kind: "password", Filename: "odd"}},
		"D": {Value: "v"},
	}
	for k := range keys {
		clearFileMeta(keys, k)
	}
	if keys["A"].Meta != nil {
		t.Errorf("A: метаданные из одной файловой метки должны исчезнуть: %+v", keys["A"].Meta)
	}
	if m := keys["B"].Meta; m == nil || m.Filename != "" || m.Kind != "" || m.Note != "note" {
		t.Errorf("B: note должен остаться, файловая метка — нет: %+v", m)
	}
	if m := keys["C"].Meta; m == nil || m.Kind != "password" || m.Filename != "" {
		t.Errorf("C: пользовательский kind должен остаться: %+v", m)
	}
	if keys["D"].Meta != nil {
		t.Errorf("D: без метаданных — no-op")
	}
}
