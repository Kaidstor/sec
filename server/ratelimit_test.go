package main

import (
	"testing"
	"time"
)

func TestRateLimiter(t *testing.T) {
	rl := NewRateLimiter(2) // burst = 2
	cur := time.Unix(0, 0)
	rl.now = func() time.Time { return cur }

	if !rl.Allow("a") || !rl.Allow("a") {
		t.Fatal("burst не пропущен")
	}
	if rl.Allow("a") {
		t.Fatal("запрос сверх burst прошёл")
	}
	if !rl.Allow("b") {
		t.Fatal("другой IP зажат чужим лимитом")
	}
	cur = cur.Add(time.Minute)
	if !rl.Allow("a") {
		t.Fatal("после паузы лимит не восстановился")
	}
}
