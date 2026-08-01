package main

import (
	"sync"
	"time"
)

// RateLimiter — token bucket по IP для claim. Перебор id и так бессмыслен
// (128 бит случайности), лимитер просто прижимает автоматический шум.
type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64 // токенов в секунду
	burst   float64
	ops     int
	now     func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// maxBuckets — жёсткий бюджет памяти: флуд с уникальных (в т.ч. спуфнутых)
// адресов не должен раздувать карту и превращать каждый Allow в O(n).
const maxBuckets = 10000

func NewRateLimiter(perMinute int) *RateLimiter {
	return &RateLimiter{
		buckets: map[string]*bucket{},
		rate:    float64(perMinute) / 60,
		burst:   float64(perMinute),
		now:     time.Now,
	}
}

func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := rl.now()
	rl.ops++
	if rl.ops%4096 == 0 {
		rl.prune(now, time.Hour)
	}
	if len(rl.buckets) >= maxBuckets {
		rl.prune(now, 10*time.Minute)
		if len(rl.buckets) >= maxBuckets {
			// бюджет важнее точности: сброс пропустит чей-то burst заново,
			// но не даст выесть память и CPU
			rl.buckets = map[string]*bucket{}
		}
	}
	b, ok := rl.buckets[ip]
	if !ok {
		b = &bucket{tokens: rl.burst, last: now}
		rl.buckets[ip] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * rl.rate
	if b.tokens > rl.burst {
		b.tokens = rl.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (rl *RateLimiter) prune(now time.Time, idle time.Duration) {
	for k, b := range rl.buckets {
		if now.Sub(b.last) > idle {
			delete(rl.buckets, k)
		}
	}
}
