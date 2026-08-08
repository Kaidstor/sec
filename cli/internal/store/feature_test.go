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

func TestStoreProjProfile(t *testing.T) {
	if ProjKey("svc", "") != "svc" {
		t.Error("без профиля — проект как есть")
	}
	if ProjKey("svc", "commercial") != "svc@commercial" {
		t.Error("с профилем — склейка через @")
	}
	if b, p := BaseAndProfile("svc@commercial"); b != "svc" || p != "commercial" {
		t.Errorf("BaseAndProfile(svc@commercial) = %q, %q", b, p)
	}
	if b, p := BaseAndProfile("svc"); b != "svc" || p != "" {
		t.Errorf("BaseAndProfile(svc) = %q, %q", b, p)
	}
}

// DisplayProj: базовый набор сервиса с профилями печатается явной формой
// "svc@" — голый "svc" в папке с default из .sec разрешился бы в профиль.
func TestDisplayProj(t *testing.T) {
	st := &Store{Projects: map[string]map[string]Secret{
		"svc":      {"K": {Value: "v"}},
		"svc@prod": {"K": {Value: "v"}},
		"plain":    {"K": {Value: "v"}},
	}}
	if got := st.DisplayProj("svc"); got != "svc@" {
		t.Errorf("база с профилями: DisplayProj(svc) = %q, ожидалось svc@", got)
	}
	if got := st.DisplayProj("svc@prod"); got != "svc@prod" {
		t.Errorf("DisplayProj(svc@prod) = %q", got)
	}
	if got := st.DisplayProj("plain"); got != "plain" {
		t.Errorf("сервис без профилей: DisplayProj(plain) = %q", got)
	}
	if got := st.DisplayRef("svc/K"); got != "svc@/K" {
		t.Errorf("DisplayRef(svc/K) = %q, ожидалось svc@/K", got)
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
