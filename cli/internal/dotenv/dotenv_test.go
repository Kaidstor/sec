package dotenv

import "testing"

func TestParseDotenv(t *testing.T) {
	src := `# комментарий
export TOKEN=abc123
QUOTED="hello world"
SINGLE='keep $literal'
ESCAPED="line1\nline2 with \"quotes\""
BAD KEY=skip
без-равно
EMPTY=
`
	kv, warns := Parse(src)
	want := map[string]string{
		"TOKEN":   "abc123",
		"QUOTED":  "hello world",
		"SINGLE":  "keep $literal",
		"ESCAPED": "line1\nline2 with \"quotes\"",
		"EMPTY":   "",
	}
	for k, v := range want {
		if kv[k] != v {
			t.Errorf("kv[%q] = %q, want %q", k, kv[k], v)
		}
	}
	if len(kv) != len(want) {
		t.Errorf("лишние ключи: %v", kv)
	}
	if len(warns) != 2 {
		t.Errorf("ожидалось 2 предупреждения (BAD KEY, без-равно), получено %v", warns)
	}
}

// Всё, что Line записал, Parse должен прочитать без искажений.
func TestDotenvRoundtrip(t *testing.T) {
	values := []string{
		"plain-token_123",
		"hello world",
		`with "quotes" inside`,
		"back\\slash",
		"multi\nline",
		"$dollar and `backtick`",
		"",
	}
	for _, v := range values {
		line := Line("KEY", v)
		kv, warns := Parse(line)
		if len(warns) > 0 {
			t.Errorf("Line(%q) → %q: неожиданные warns %v", v, line, warns)
		}
		if kv["KEY"] != v {
			t.Errorf("roundtrip %q → %q → %q", v, line, kv["KEY"])
		}
	}
}
