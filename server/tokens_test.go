package main

import (
	"os"
	"strings"
	"testing"
)

func TestTokenIssueVerify(t *testing.T) {
	tf := NewTokenFile(t.TempDir())
	token, err := tf.Issue("kai")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(token, "sst_") {
		t.Fatalf("неожиданный формат токена %q", token)
	}
	name, ok := tf.Verify(token)
	if !ok || name != "kai" {
		t.Fatalf("Verify = (%q, %v), want (kai, true)", name, ok)
	}
	if _, ok := tf.Verify("sst_wrong"); ok {
		t.Fatal("чужой токен прошёл проверку")
	}
	if _, ok := tf.Verify(""); ok {
		t.Fatal("пустой токен прошёл проверку")
	}
}

func TestTokenFileHoldsOnlyHash(t *testing.T) {
	tf := NewTokenFile(t.TempDir())
	token, err := tf.Issue("kai")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(tf.path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), token) {
		t.Fatal("значение токена попало в tokens.json")
	}
}

func TestTokenDuplicateAndRemove(t *testing.T) {
	tf := NewTokenFile(t.TempDir())
	token, err := tf.Issue("kai")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tf.Issue("kai"); err == nil {
		t.Fatal("повторный Issue с тем же именем должен падать")
	}
	if err := tf.Remove("kai"); err != nil {
		t.Fatal(err)
	}
	if _, ok := tf.Verify(token); ok {
		t.Fatal("отозванный токен всё ещё проходит")
	}
	if err := tf.Remove("kai"); err == nil {
		t.Fatal("Remove несуществующего должен падать")
	}
}
