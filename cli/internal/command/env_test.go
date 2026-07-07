package command

import (
	"strings"
	"testing"
)

func TestMergedEnv(t *testing.T) {
	t.Setenv("SEC_TEST_EXISTING", "old")
	env := mergedEnv(map[string]string{
		"SEC_TEST_EXISTING": "new",
		"SEC_TEST_ADDED":    "value",
	})
	got := map[string]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		got[k] = v
	}
	if got["SEC_TEST_EXISTING"] != "new" {
		t.Errorf("существующая переменная должна быть перекрыта, получено %q", got["SEC_TEST_EXISTING"])
	}
	if got["SEC_TEST_ADDED"] != "value" {
		t.Errorf("новая переменная не добавлена")
	}
	// без дублей
	seen := map[string]int{}
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		seen[k]++
	}
	for k, n := range seen {
		if n > 1 {
			t.Errorf("дубликат %q в env (%d раз)", k, n)
		}
	}
}
