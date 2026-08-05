package command

import (
	"bytes"
	"strings"
	"testing"

	"github.com/kaidstor/sec/internal/store"
)

func TestNormalizeShareURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"share.kaidstor.ru", "https://share.kaidstor.ru"},
		{"https://share.kaidstor.ru/", "https://share.kaidstor.ru"},
		{"http://localhost:8080", "http://localhost:8080"},
		{"  share.kaidstor.ru  ", "https://share.kaidstor.ru"},
	}
	for _, c := range cases {
		if got := normalizeShareURL(c.in); got != c.want {
			t.Errorf("normalizeShareURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestHostOf(t *testing.T) {
	if got := hostOf("https://share.kaidstor.ru"); got != "share.kaidstor.ru" {
		t.Errorf("hostOf = %q", got)
	}
}

func packTestKeys() map[string]store.Secret {
	return map[string]store.Secret{
		"B_TOKEN": {Value: "tok-b"},
		"A_URL":   {Value: "https://x", Meta: &store.Meta{Kind: "config"}},
		"CERT": {Value: "AAEC", Enc: store.EncB64,
			Meta: &store.Meta{Kind: "file", Filename: "/tmp/server.p12", FileMode: "0640"}},
	}
}

func TestPackEntriesAllSorted(t *testing.T) {
	entries, err := packEntries(packTestKeys(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("entries: %+v", entries)
	}
	for i, want := range []string{"A_URL", "B_TOKEN", "CERT"} {
		if entries[i].Key != want {
			t.Fatalf("порядок: %d = %s, want %s", i, entries[i].Key, want)
		}
	}
	cert := entries[2]
	if cert.Filename != "server.p12" || cert.Mode != "0640" || cert.Kind != "file" {
		t.Fatalf("файловая запись: %+v", cert)
	}
	if !bytes.Equal(cert.Data, []byte{0, 1, 2}) {
		t.Fatalf("бинарные данные не раскодировались из base64: % x", cert.Data)
	}
	if entries[0].Kind != "config" || entries[0].Filename != "" {
		t.Fatalf("текстовая запись: %+v", entries[0])
	}
}

func TestPackEntriesOnly(t *testing.T) {
	entries, err := packEntries(packTestKeys(), "B_TOKEN, A_URL")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Key != "B_TOKEN" || entries[1].Key != "A_URL" {
		t.Fatalf("only сохраняет порядок перечисления: %+v", entries)
	}
	if _, err := packEntries(packTestKeys(), "B_TOKEN,NOPE"); err == nil || !strings.Contains(err.Error(), "NOPE") {
		t.Fatalf("пропавший ключ не пойман: %v", err)
	}
	if _, err := packEntries(packTestKeys(), " , "); err == nil {
		t.Fatal("пустой --only принят")
	}
}

func TestPackEntriesSizeCap(t *testing.T) {
	keys := map[string]store.Secret{
		"BIG": {Value: strings.Repeat("x", maxFileSecret)},
		"ONE": {Value: "y"},
	}
	if _, err := packEntries(keys, ""); err == nil {
		t.Fatal("превышение суммарного предела не поймано")
	}
	if _, err := packEntries(keys, "ONE"); err != nil {
		t.Fatalf("--only в пределах лимита: %v", err)
	}
}

// _share намеренно не проходит projRe: пользователь не может задеть служебный
// проект через set/rm/link — тест страхует от «починки» регэкспа.
func TestShareConfigProjectReserved(t *testing.T) {
	if projRe.MatchString(shareConfigProject) {
		t.Fatalf("%q стал валидным именем проекта — служебный конфиг share больше не защищён", shareConfigProject)
	}
}
