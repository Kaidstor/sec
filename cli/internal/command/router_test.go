package command

import (
	"strings"
	"testing"

	"github.com/kaidstor/sec/internal/store"
)

// Файловые секреты (kind: file и бинарные) в env-инъекцию по умолчанию не
// попадают: env копируется каждому дочернему процессу и упирается в ARG_MAX.
func TestSelectKeysSkipsFileSecrets(t *testing.T) {
	keys := map[string]store.Secret{
		"TOKEN": {Value: "tok"},
		"PEM":   {Value: "pem-text", Meta: &store.Meta{Kind: "file", Filename: "app.pem"}},
		"BIN":   {Value: "AAAA", Enc: store.EncB64},
	}
	out := selectKeys(keys, "", "proj", false)
	if len(out) != 1 || out["TOKEN"] != "tok" {
		t.Errorf("без --include-files должен остаться только TOKEN: %v", names(out))
	}
	out = selectKeys(keys, "", "proj", true)
	if len(out) != 2 || out["PEM"] != "pem-text" {
		t.Errorf("--include-files возвращает kind:file, но не бинарные: %v", names(out))
	}
	// явный --only побеждает пропуск по kind: file
	out = selectKeys(keys, "PEM,TOKEN", "proj", false)
	if len(out) != 2 || out["PEM"] != "pem-text" {
		t.Errorf("--only с явным именем должен инжектить kind:file: %v", names(out))
	}
}

func names(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// splitProfile — разбор "service[@profile]": explicit различает "svc" (дефолт
// из .sec применим) и "svc@" (явно базовый набор).
func TestSplitProfile(t *testing.T) {
	cases := []struct {
		in, base, profile string
		explicit          bool
	}{
		{"svc", "svc", "", false},
		{"svc@prod", "svc", "prod", true},
		{"svc@", "svc", "", true},
		{"", "", "", false},
		{"@prod", "", "prod", true}, // база пустая — resolveProjP такое отвергает
	}
	for _, c := range cases {
		b, p, ex := splitProfile(c.in)
		if b != c.base || p != c.profile || ex != c.explicit {
			t.Errorf("splitProfile(%q) = %q, %q, %v; ожидалось %q, %q, %v",
				c.in, b, p, ex, c.base, c.profile, c.explicit)
		}
	}
}

func TestDefaultBareFlag(t *testing.T) {
	cases := []struct{ in, want string }{
		{"--out", "--out ."},
		{"-out", "-out ."},
		{"--out --peek", "--out . --peek"},
		{"--out path", "--out path"},
		{"--out=path", "--out=path"},
		{"-n 5 --out", "-n 5 --out ."},
		{"", ""},
	}
	for _, c := range cases {
		var in []string
		if c.in != "" {
			in = strings.Fields(c.in)
		}
		if got := strings.Join(defaultBareFlag(in, "out", "."), " "); got != c.want {
			t.Errorf("defaultBareFlag(%q) = %q, ожидалось %q", c.in, got, c.want)
		}
	}
}
