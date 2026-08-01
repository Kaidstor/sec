package main

import (
	"strings"
	"testing"
)

func TestBase62KnownVectors(t *testing.T) {
	cases := []struct {
		in   []byte
		want string
	}{
		{[]byte{0}, "0"},
		{[]byte{1}, "1"},
		{[]byte{61}, "z"},
		{[]byte{62}, "10"},
		{[]byte{0xFF}, "47"}, // 255 = 4*62 + 7
	}
	for _, c := range cases {
		if got := base62(c.in); got != c.want {
			t.Errorf("base62(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNewIDShape(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 10000; i++ {
		id := NewID()
		if len(id) < 16 || len(id) > 22 {
			t.Fatalf("неожиданная длина id %q (%d)", id, len(id))
		}
		for _, r := range id {
			if !strings.ContainsRune(base62Alphabet, r) {
				t.Fatalf("символ вне алфавита в %q", id)
			}
		}
		if seen[id] {
			t.Fatalf("дубль id на %d итерации: %q", i, id)
		}
		seen[id] = true
	}
}

func TestIDPassesValidation(t *testing.T) {
	for i := 0; i < 100; i++ {
		if id := NewID(); !idRe.MatchString(id) {
			t.Fatalf("NewID %q не проходит серверную валидацию", id)
		}
	}
}
