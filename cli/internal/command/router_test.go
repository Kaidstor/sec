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

func TestDefaultBareFlag(t *testing.T) {
	cases := []struct{ in, want string }{
		{"--out", "--out ."},
		{"-out", "-out ."},
		{"--out --peek", "--out . --peek"},
		{"--out path", "--out path"},
		{"--out=path", "--out=path"},
		{"-e prod --out", "-e prod --out ."},
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
