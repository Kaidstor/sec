package command

import (
	"strings"
	"testing"
	"time"

	"github.com/kaidstor/sec/internal/store"
)

func TestParseHumanDuration(t *testing.T) {
	ok := map[string]time.Duration{
		"90d": 90 * 24 * time.Hour,
		"2w":  14 * 24 * time.Hour,
		"12h": 12 * time.Hour,
		"30m": 30 * time.Minute,
	}
	for in, want := range ok {
		got, err := parseHumanDuration(in)
		if err != nil || got != want {
			t.Errorf("parseHumanDuration(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "abc", "xd", "d"} {
		if _, err := parseHumanDuration(bad); err == nil {
			t.Errorf("parseHumanDuration(%q): ожидалась ошибка", bad)
		}
	}
}

func TestResolveExpiresAt(t *testing.T) {
	// абсолютная дата
	got, err := resolveExpiresAt("2030-01-15")
	if err != nil {
		t.Fatal(err)
	}
	if tt, _ := time.Parse(time.RFC3339, got); tt.Year() != 2030 || tt.Month() != 1 || tt.Day() != 15 {
		t.Errorf("дата разобрана неверно: %s", got)
	}
	// интервал от сейчас
	got, err = resolveExpiresAt("10d")
	if err != nil {
		t.Fatal(err)
	}
	tt, _ := time.Parse(time.RFC3339, got)
	if d := time.Until(tt); d < 9*24*time.Hour || d > 11*24*time.Hour {
		t.Errorf("интервал 10d дал %v", d)
	}
	if _, err := resolveExpiresAt("не-дата-не-интервал"); err == nil {
		t.Error("ожидалась ошибка на мусоре")
	}
}

func TestDueAt(t *testing.T) {
	// нет метаданных — политики нет
	if _, _, ok := dueAt(store.Secret{Value: "x"}); ok {
		t.Error("без Meta не должно быть срока")
	}
	// rotate-every считается от UpdatedAt
	base := time.Now().Add(-100 * 24 * time.Hour)
	s := store.Secret{Value: "x", UpdatedAt: base.Format(time.RFC3339), Meta: &store.Meta{RotateEvery: "90d"}}
	due, src, ok := dueAt(s)
	if !ok || src != "rotate-every" {
		t.Fatalf("ожидался rotate-every, got ok=%v src=%q", ok, src)
	}
	if !time.Now().After(due) {
		t.Error("90d от 100 дней назад должно быть просрочено")
	}
	// expires приоритетнее rotate-every
	exp := time.Now().Add(24 * time.Hour).Format(time.RFC3339)
	s.Meta.ExpiresAt = exp
	_, src, _ = dueAt(s)
	if src != "expires" {
		t.Errorf("expires должен побеждать rotate-every, got %q", src)
	}
}

func TestParseSecFile(t *testing.T) {
	text := "# .sec\nproject: some-bot\nenvs: commercial, max\ndefault: commercial\nkeys: BOT_TOKEN, DB_PASS\nEXTRA_KEY\n"
	c, warns := parseSecFile(text)
	if c.Project != "some-bot" {
		t.Errorf("project = %q", c.Project)
	}
	if strings.Join(c.Envs, ",") != "commercial,max" {
		t.Errorf("envs = %v", c.Envs)
	}
	if c.Default != "commercial" {
		t.Errorf("default = %q", c.Default)
	}
	if strings.Join(c.Keys, ",") != "BOT_TOKEN,DB_PASS,EXTRA_KEY" {
		t.Errorf("keys = %v", c.Keys)
	}
	if len(warns) != 0 {
		t.Errorf("неожиданные предупреждения: %v", warns)
	}
	if _, w := parseSecFile("bogus: x\n"); len(w) != 1 {
		t.Errorf("ожидалось 1 предупреждение о неизвестной директиве, got %v", w)
	}
}
