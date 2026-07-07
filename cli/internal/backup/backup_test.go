package backup

import (
	"bytes"
	"testing"
)

func TestBackupRoundtrip(t *testing.T) {
	plain := []byte(`{"projects":{"demo":{"K":{"value":"v"}}}}`)
	blob, err := Seal(plain, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if string(blob[:8]) != "SECBAK03" {
		t.Errorf("ожидался формат SECBAK03, получено %q", blob[:8])
	}
	got, err := Open(blob, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("roundtrip mismatch: %s", got)
	}
	if _, err := Open(blob, "wrong passphrase"); err == nil {
		t.Error("ожидалась ошибка на неверной passphrase")
	}
	if _, err := Open([]byte("garbage"), "x"); err == nil {
		t.Error("ожидалась ошибка на мусорном файле")
	}
}

// битый заголовок с абсурдной памятью должен отвергаться до вызова Argon2.
func TestBackupRejectsInsaneParams(t *testing.T) {
	blob, err := Seal([]byte("{}"), "pw-correct")
	if err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), blob...)
	bad[8], bad[9], bad[10], bad[11] = 0xff, 0xff, 0xff, 0xff // mem = 4 ГиБ+ в KiB
	if _, err := Open(bad, "pw-correct"); err == nil {
		t.Error("ожидалась ошибка на некорректных параметрах Argon2")
	}
}
