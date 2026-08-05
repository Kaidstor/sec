package command

import (
	"strings"
	"testing"

	"github.com/kaidstor/sec/internal/store"
)

// Merge-режим правит только разошедшиеся и недостающие ключи: чужие ключи файла,
// его комментарии и порядок строк остаются — именно ради этого deploy не
// пересобирает файл как export.
func TestBuildEnvFileMergeKeepsForeignKeys(t *testing.T) {
	keys, file := envDiffFixture()
	orig := "# прод-конфиг\nWHOIS_VERSION=1.2.3\nWHOXY_API_KEY=same-secret-value\n" +
		"WHOIS_HISTORY_PROVIDERS=whoxy,ripe\nDOMAINATOR_DB_URL=postgres://host-only-creds\n"
	file["WHOIS_VERSION"] = "1.2.3" // ключ, которого в сторе нет, — его патчит CI

	entries := compareEnvFile(keys, file, []byte("test-master-key"))
	out, written := buildEnvFile("whois", orig, keys, entries, false)

	for _, keep := range []string{"# прод-конфиг", "WHOIS_VERSION=1.2.3", "DOMAINATOR_DB_URL=postgres://host-only-creds"} {
		if !strings.Contains(out, keep) {
			t.Errorf("merge потерял чужую строку %q:\n%s", keep, out)
		}
	}
	if !strings.Contains(out, "WHOIS_HISTORY_PROVIDERS=whoxy\n") {
		t.Errorf("разошедшийся ключ не обновлён:\n%s", out)
	}
	if !strings.Contains(out, "REDIS_URL=redis://store-only") {
		t.Errorf("недостающий ключ не дописан:\n%s", out)
	}
	if strings.Join(written, ",") != "REDIS_URL,WHOIS_HISTORY_PROVIDERS" {
		t.Errorf("записанными считаются только изменённые ключи: %v", written)
	}
	// совпадающий ключ не переписывается — иначе каждый деплой давал бы шум в diff
	if strings.Count(out, "WHOXY_API_KEY") != 1 {
		t.Errorf("совпадающий ключ тронут:\n%s", out)
	}
}

func TestBuildEnvFileReplaceRebuilds(t *testing.T) {
	keys, file := envDiffFixture()
	orig := "# прод-конфиг\nDOMAINATOR_DB_URL=postgres://host-only-creds\nWHOXY_API_KEY=same-secret-value\n"
	entries := compareEnvFile(keys, file, []byte("test-master-key"))
	out, written := buildEnvFile("whois", orig, keys, entries, true)

	if strings.Contains(out, "DOMAINATOR_DB_URL") {
		t.Errorf("--replace должен выкидывать ключи, которых нет в сторе:\n%s", out)
	}
	if !strings.HasPrefix(out, "# сгенерировано sec из проекта whois") {
		t.Errorf("нет шапки сгенерированного файла:\n%s", out)
	}
	if len(written) != len(keys) {
		t.Errorf("--replace пишет все ключи проекта: %v", written)
	}
}

// Файловые (kind: file) и бинарные ключи в env-файл не едут, --only сужает набор.
func TestEnvKeysOfSkipsFiles(t *testing.T) {
	st := &store.Store{Projects: map[string]map[string]store.Secret{
		"whois": {
			"TOKEN":  {Value: "plain"},
			"CERT":   {Value: "-----BEGIN----", Meta: &store.Meta{Kind: "file"}},
			"P12":    {Value: "YmluYXJ5", Enc: store.EncB64},
			"REDIS":  {Value: "redis://x"},
			"UNUSED": {Value: "y"},
		},
	}}
	keys := envKeysOf(st, "whois", "")
	if _, ok := keys["CERT"]; ok {
		t.Error("kind: file не должен попадать в env-файл")
	}
	if _, ok := keys["P12"]; ok {
		t.Error("бинарный секрет не должен попадать в env-файл")
	}
	if len(keys) != 3 {
		t.Errorf("осталось ключей: %v", store.SortedKeys(keys))
	}
	if got := store.SortedKeys(envKeysOf(st, "whois", "TOKEN, REDIS")); strings.Join(got, ",") != "REDIS,TOKEN" {
		t.Errorf("--only не сузил набор: %v", got)
	}
}

func TestSortedUnion(t *testing.T) {
	got := sortedUnion([]string{"B", "A"}, []string{"C", "A"})
	if strings.Join(got, ",") != "A,B,C" {
		t.Errorf("sortedUnion = %v", got)
	}
}
