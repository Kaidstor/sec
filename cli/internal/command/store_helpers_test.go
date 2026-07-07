package command

import (
	"testing"

	"github.com/kaidstor/sec/internal/store"
)

func TestEditBlock(t *testing.T) {
	st := &store.Store{Version: 1, Projects: map[string]map[string]store.Secret{
		"app":  {"OWN": {Value: "v"}, "R": {Ref: "base/X"}},
		"base": {"X": {Value: "base-x"}},
	}, Extends: map[string][]string{"app": {"base"}}}

	if msg := editBlock(st, "app", "OWN"); msg != "" {
		t.Errorf("собственное значение должно быть редактируемым, got %q", msg)
	}
	if msg := editBlock(st, "app", "NEW"); msg != "" {
		t.Errorf("новый ключ должен быть редактируемым, got %q", msg)
	}
	if msg := editBlock(st, "app", "R"); msg == "" {
		t.Error("ссылку нельзя редактировать напрямую — ждали блокировку")
	}
	if msg := editBlock(st, "app", "X"); msg == "" {
		t.Error("унаследованный ключ нельзя редактировать напрямую — ждали блокировку")
	}
}
