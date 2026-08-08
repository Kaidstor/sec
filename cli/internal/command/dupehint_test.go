package command

import (
	"strings"
	"testing"

	"github.com/kaidstor/sec/internal/store"
)

func dupeTestStore() *store.Store {
	return &store.Store{Projects: map[string]map[string]store.Secret{
		"apple": {
			"APPLE_PASSWORD": {Value: "s3cret", UpdatedAt: "2025-01-01T00:00:00Z"},
		},
		"sql-kai": {
			"APPLE_PASSWORD": {Value: "s3cret", UpdatedAt: "2026-01-01T00:00:00Z"},
			"GITLAB_TOKEN":   {Value: "glpat-xxx", UpdatedAt: "2026-01-01T00:00:00Z"},
			"LINKED":         {Ref: "apple/APPLE_PASSWORD", UpdatedAt: "2026-01-01T00:00:00Z"},
		},
	}}
}

func TestDupeHintsSuggestsLink(t *testing.T) {
	mkey := []byte("k")
	hints := dupeHints(dupeTestStore(), mkey, "sql-kai", []string{"APPLE_PASSWORD", "GITLAB_TOKEN"})
	if len(hints) != 1 {
		t.Fatalf("ожидалась одна подсказка, получено %d: %v", len(hints), hints)
	}
	want := "значение sql-kai/APPLE_PASSWORD уже есть в apple/APPLE_PASSWORD — вместо копии можно ссылку: sec link sql-kai/APPLE_PASSWORD apple/APPLE_PASSWORD --force"
	if hints[0] != want {
		t.Errorf("подсказка:\n got %q\nwant %q", hints[0], want)
	}
}

func TestDupeHintsSkipsRefsAndUnique(t *testing.T) {
	mkey := []byte("k")
	// LINKED — ссылка на то же значение, но собственного значения у неё нет:
	// дублем не считается и в подсказку не попадает
	hints := dupeHints(dupeTestStore(), mkey, "sql-kai", []string{"GITLAB_TOKEN", "LINKED"})
	if len(hints) != 0 {
		t.Errorf("уникальное значение и ссылка не должны давать подсказок: %v", hints)
	}
}

func TestDupeHintsBatchGivesOneLine(t *testing.T) {
	mkey := []byte("k")
	st := &store.Store{Projects: map[string]map[string]store.Secret{
		"proj": {
			"A": {Value: "same", UpdatedAt: "2026-01-01T00:00:00Z"},
			"B": {Value: "same", UpdatedAt: "2026-01-01T00:00:00Z"},
		},
	}}
	hints := dupeHints(st, mkey, "proj", []string{"A", "B"})
	if len(hints) != 1 {
		t.Errorf("пачка одинаковых значений должна дать одну строку, не зеркальную пару: %v", hints)
	}
}

func TestDupeHintsEncSeparatesBinary(t *testing.T) {
	mkey := []byte("k")
	st := &store.Store{Projects: map[string]map[string]store.Secret{
		"a": {"TEXT": {Value: "aGVsbG8=", UpdatedAt: "2025-01-01T00:00:00Z"}},
		"b": {"FILE": {Value: "aGVsbG8=", Enc: store.EncB64, UpdatedAt: "2026-01-01T00:00:00Z"}},
	}}
	if hints := dupeHints(st, mkey, "b", []string{"FILE"}); len(hints) != 0 {
		t.Errorf("текст, равный base64 бинарного, — не дубль: %v", hints)
	}
}

func TestDupeHintsProfileForms(t *testing.T) {
	mkey := []byte("k")
	st := &store.Store{Projects: map[string]map[string]store.Secret{
		"shared":      {"TOKEN": {Value: "v", UpdatedAt: "2025-01-01T00:00:00Z"}},
		"shared@prod": {"TOKEN": {Value: "v2", UpdatedAt: "2025-01-01T00:00:00Z"}},
		"svc@prod":    {"TOKEN": {Value: "v2", UpdatedAt: "2026-01-01T00:00:00Z"}},
		"svc@staging": {"TOKEN": {Value: "v", UpdatedAt: "2026-01-01T00:00:00Z"}},
		"plain":       {"TOKEN": {Value: "v2", UpdatedAt: "2026-06-01T00:00:00Z"}},
	}}

	// равные профили (svc@prod ↔ shared@prod) — профиль родителя наследуется,
	// в команде опускается
	hints := dupeHints(st, mkey, "svc@prod", []string{"TOKEN"})
	if len(hints) != 1 || !strings.Contains(hints[0], "sec link svc@prod/TOKEN shared/TOKEN --force") {
		t.Errorf("равные профили: ожидался родитель без @: %v", hints)
	}

	// ключ с профилем, кандидат из базового набора → parent@ (явно без профиля)
	hints = dupeHints(st, mkey, "svc@staging", []string{"TOKEN"})
	if len(hints) != 1 || !strings.Contains(hints[0], "sec link svc@staging/TOKEN shared@/TOKEN --force") {
		t.Errorf("базовый родитель при ключе с профилем — shared@/: %v", hints)
	}

	// ключ без профиля, старейший кандидат с профилем → явный @prod у родителя
	hints = dupeHints(st, mkey, "plain", []string{"TOKEN"})
	if len(hints) != 1 || !strings.Contains(hints[0], "sec link plain/TOKEN shared@prod/TOKEN --force") {
		t.Errorf("ожидался родитель shared@prod (старейший кандидат): %v", hints)
	}
}
