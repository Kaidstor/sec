package store

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestPutSecretHistory(t *testing.T) {
	m := map[string]Secret{}

	if existed := Put(m, "K", "v1"); existed {
		t.Error("новый ключ не должен считаться существовавшим")
	}
	if len(m["K"].History) != 0 {
		t.Error("у нового ключа не должно быть истории")
	}

	Put(m, "K", "v2")
	if h := m["K"].History; len(h) != 1 || h[0].Value != "v1" {
		t.Errorf("ожидалась история [v1], получено %+v", h)
	}

	// то же значение — история не растёт
	Put(m, "K", "v2")
	if len(m["K"].History) != 1 {
		t.Errorf("одинаковое значение не должно плодить историю: %+v", m["K"].History)
	}

	// переполнение: держим только maxHistory последних
	for i := 3; i <= 10; i++ {
		Put(m, "K", string(rune('a'+i)))
	}
	if len(m["K"].History) != maxHistory {
		t.Errorf("история должна быть обрезана до %d, получено %d", maxHistory, len(m["K"].History))
	}
}

func TestUndoRedoWalk(t *testing.T) {
	m := map[string]Secret{}
	Put(m, "K", "v1")
	Put(m, "K", "v2")
	Put(m, "K", "v3") // Value=v3, History=[v2,v1]

	s := m["K"]
	// undo идёт вглубь истории: v3 -> v2 -> v1, затем стена
	var ok bool
	if s, ok = s.Undo(); !ok || s.Value != "v2" {
		t.Fatalf("undo1: ok=%v val=%q", ok, s.Value)
	}
	if s, ok = s.Undo(); !ok || s.Value != "v1" {
		t.Fatalf("undo2: ok=%v val=%q", ok, s.Value)
	}
	if _, ok = s.Undo(); ok {
		t.Error("после самой старой версии undo должен упереться в стену")
	}
	// redo возвращает вперёд: v1 -> v2 -> v3, затем стена
	if s, ok = s.Redo(); !ok || s.Value != "v2" {
		t.Fatalf("redo1: ok=%v val=%q", ok, s.Value)
	}
	if s, ok = s.Redo(); !ok || s.Value != "v3" {
		t.Fatalf("redo2: ok=%v val=%q", ok, s.Value)
	}
	if _, ok = s.Redo(); ok {
		t.Error("после самой свежей версии redo должен упереться в стену")
	}
}

func TestSetClearsRedo(t *testing.T) {
	m := map[string]Secret{}
	Put(m, "K", "v1")
	Put(m, "K", "v2") // Value=v2, History=[v1]
	m["K"], _ = m["K"].Undo()
	if m["K"].Value != "v1" || len(m["K"].RedoStack) != 1 {
		t.Fatalf("после undo ожидалось Value=v1, Redo=[v2]; получено %+v", m["K"])
	}
	// новое значение поверх отменённого стирает redo-стек
	Put(m, "K", "v3")
	if len(m["K"].RedoStack) != 0 {
		t.Errorf("set нового значения должен обнулять redo, получено %+v", m["K"].RedoStack)
	}
	if h := m["K"].History; len(h) != 1 || h[0].Value != "v1" {
		t.Errorf("ожидалась история [v1], получено %+v", h)
	}
}

func TestForgetScrubsHistory(t *testing.T) {
	m := map[string]Secret{}
	Put(m, "K", "v1")
	Put(m, "K", "v2")
	m["K"], _ = m["K"].Undo() // разведём и историю, и redo
	s := m["K"].Forget()
	if len(s.History) != 0 || len(s.RedoStack) != 0 {
		t.Errorf("forget должен вычистить историю и redo, получено %+v", s)
	}
	if s.Value != m["K"].Value {
		t.Errorf("forget должен сохранить текущее значение: было %q, стало %q", m["K"].Value, s.Value)
	}
}

func TestMaskValue(t *testing.T) {
	cases := map[string]string{
		"":                 "····",
		"short":            "····",
		"1234567":          "····",
		"12345678":         "12…78",
		"sk-abcdef1234xyz": "sk…yz",
		"пароль-секретный": "па…ый", // юникод по рунам, не байтам
	}
	for in, want := range cases {
		if got := MaskValue(in); got != want {
			t.Errorf("MaskValue(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	plain := []byte(`{"projects":{}}`)

	ct, err := encrypt(key, plain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decrypt(key, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("roundtrip mismatch: %s", got)
	}

	wrong := make([]byte, 32)
	_, _ = rand.Read(wrong)
	if _, err := decrypt(wrong, ct); err == nil {
		t.Error("ожидалась ошибка на неверном ключе")
	}
	if _, err := decrypt(key, []byte("garbage")); err == nil {
		t.Error("ожидалась ошибка на мусорных данных")
	}
}
