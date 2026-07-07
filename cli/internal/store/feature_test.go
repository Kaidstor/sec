package store

import (
	"strings"
	"testing"
)

func TestFingerprintKeyed(t *testing.T) {
	k1 := []byte("0123456789abcdef0123456789abcdef")
	k2 := []byte("ffffffffffffffffffffffffffffffff")
	a := Fingerprint(k1, "secret-value")
	// стабилен
	if a != Fingerprint(k1, "secret-value") {
		t.Error("отпечаток должен быть стабильным")
	}
	// другое значение → другой отпечаток
	if a == Fingerprint(k1, "secret-value2") {
		t.Error("разные значения — разные отпечатки")
	}
	// другой мастер-ключ → другой отпечаток (не сравним с чужим стором)
	if a == Fingerprint(k2, "secret-value") {
		t.Error("разные ключи — разные отпечатки")
	}
	if !strings.HasPrefix(a, "fp:") || len(a) != len("fp:")+16 {
		t.Errorf("формат отпечатка неожиданный: %q", a)
	}
}

func TestStoreProjEnv(t *testing.T) {
	if ProjKey("svc", "") != "svc" {
		t.Error("без инстанса — проект как есть")
	}
	if ProjKey("svc", "commercial") != "svc@commercial" {
		t.Error("с инстансом — склейка через @")
	}
	if b, e := BaseAndEnv("svc@commercial"); b != "svc" || e != "commercial" {
		t.Errorf("BaseAndEnv(svc@commercial) = %q, %q", b, e)
	}
	if b, e := BaseAndEnv("svc"); b != "svc" || e != "" {
		t.Errorf("BaseAndEnv(svc) = %q, %q", b, e)
	}
}

func TestMergeStores(t *testing.T) {
	dst := &Store{Version: 1, Projects: map[string]map[string]Secret{
		"app": {"A": {Value: "local-a"}, "B": {Value: "same"}},
	}}
	src := &Store{Version: 1, Projects: map[string]map[string]Secret{
		"app": {"A": {Value: "remote-a"}, "B": {Value: "same"}, "C": {Value: "new-c", Meta: &Meta{Note: "из src"}}},
	}}
	added, updated := Merge(dst, src)
	if dst.Projects["app"]["A"].Value != "remote-a" {
		t.Error("значение из src должно победить")
	}
	if len(dst.Projects["app"]["A"].History) == 0 || dst.Projects["app"]["A"].History[0].Value != "local-a" {
		t.Error("вытесненное локальное значение должно уйти в историю")
	}
	if dst.Projects["app"]["C"].Meta == nil || dst.Projects["app"]["C"].Meta.Note != "из src" {
		t.Error("метаданные нового ключа должны подтянуться из src")
	}
	if added != 1 || updated != 1 { // C добавлен, A обновлён, B без изменений
		t.Errorf("added=%d updated=%d, want 1/1", added, updated)
	}
}
