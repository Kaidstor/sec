package share

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestEncodeDecodeRoundtrip(t *testing.T) {
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	for _, env := range []Envelope{
		{Type: "text", Data: []byte("s3cret-value\nсо второй строкой")},
		{Type: "file", Filename: "server.p12", Mode: "0644", Data: []byte{0, 1, 2, 0xFF, 0xFE}},
	} {
		blob, err := Encode(key, env)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Decode(key, blob)
		if err != nil {
			t.Fatal(err)
		}
		if got.Type != env.Type || got.Filename != env.Filename ||
			got.Mode != env.Mode || !bytes.Equal(got.Data, env.Data) {
			t.Fatalf("roundtrip %s: %+v != %+v", env.Type, got, env)
		}
	}
}

func TestBlobHeader(t *testing.T) {
	key, _ := NewKey()
	blob, err := Encode(key, Envelope{Type: "text", Data: []byte("x")})
	if err != nil {
		t.Fatal(err)
	}
	if string(blob[:len(Magic)]) != Magic {
		t.Fatalf("нет магии: % x", blob[:12])
	}
	if blob[len(Magic)] != Version {
		t.Fatalf("версия %d, want %d", blob[len(Magic)], Version)
	}
	if len(blob) <= headerLen+nonceLen+16 {
		t.Fatalf("блоб подозрительно короткий: %d", len(blob))
	}
}

func TestDecodeRejectsTamperAndWrongKey(t *testing.T) {
	key, _ := NewKey()
	blob, err := Encode(key, Envelope{Type: "text", Data: []byte("value")})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(blob); i += 7 {
		bad := bytes.Clone(blob)
		bad[i] ^= 0x01
		if _, err := Decode(key, bad); err == nil {
			t.Fatalf("порча байта %d прошла незамеченной", i)
		}
	}
	other, _ := NewKey()
	if _, err := Decode(other, blob); err == nil {
		t.Fatal("чужой ключ расшифровал блоб")
	}
	if _, err := Decode(key[:16], blob); err == nil {
		t.Fatal("короткий ключ принят")
	}
	if _, err := Decode(key, []byte("не блоб")); err == nil {
		t.Fatal("мусор принят за блоб")
	}
}

// TestGoldenVectorDecode — контракт формата с reveal.html: правка раскладки
// AAD/nonce/конверта пройдёт round-trip-тесты, но сломает расшифровку в
// браузере; этот пиненый блоб ловит такую правку. Не перегенерировать молча —
// при смене формата поднимать Version и чинить обе стороны.
func TestGoldenVectorDecode(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, KeyLen)
	blob, err := hex.DecodeString(
		"7365637368617265018425d6581fa315b91e2fbbaca4d451fe071afb9edbaaf8" +
			"f9356b7e6e34425a7252636349d64065b60364d4d6f56872d04c5959751ad31f" +
			"f2670483d5bc0ea14c434289df5906f92a89eec01164cc6d9f62173c")
	if err != nil {
		t.Fatal(err)
	}
	env, err := Decode(key, blob)
	if err != nil {
		t.Fatalf("пиненый блоб не расшифровался — формат разъехался с reveal.html: %v", err)
	}
	if env.Type != "text" || string(env.Data) != "golden-vector-π" {
		t.Fatalf("расшифровалось не то: %+v", env)
	}
}

func TestSecretURLAndIDFromURL(t *testing.T) {
	key := bytes.Repeat([]byte{0xAB}, KeyLen)
	u := SecretURL("https://share.example.com/", "Ab12", key)
	want := "https://share.example.com/s/Ab12#"
	if len(u) <= len(want) || u[:len(want)] != want {
		t.Fatalf("SecretURL = %q", u)
	}
	for _, c := range []struct{ in, want string }{
		{u, "Ab12"},
		{"https://share.example.com/s/Ab12", "Ab12"},
		{"Ab12", "Ab12"},
		{"https://share.example.com/s/Ab12/", "Ab12"},
	} {
		if got := IDFromURL(c.in); got != c.want {
			t.Errorf("IDFromURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
