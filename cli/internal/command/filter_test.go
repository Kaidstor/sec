package command

import "testing"

func TestMatchFilterSubstring(t *testing.T) {
	cases := []struct {
		pat, name string
		want      bool
	}{
		{"", "GITHUB_TOKEN", true},      // пустой шаблон — фильтра нет
		{"token", "GITHUB_TOKEN", true}, // регистр не важен
		{"GITHUB", "github", true},
		{"hub_t", "GITHUB_TOKEN", true}, // подстрока, не только префикс
		{"gitlab", "GITHUB_TOKEN", false},
	}
	for _, c := range cases {
		if got := matchFilter(c.pat, c.name); got != c.want {
			t.Errorf("matchFilter(%q, %q) = %v, ждали %v", c.pat, c.name, got, c.want)
		}
	}
}

func TestMatchFilterGlob(t *testing.T) {
	cases := []struct {
		pat, name string
		want      bool
	}{
		{"*_TOKEN", "GITHUB_TOKEN", true},
		{"*_TOKEN", "TOKEN_GITHUB", false},
		{"db_*", "DB_URL", true},
		{"*", "что угодно", true},
		{"??_URL", "DB_URL", true},
		{"?_URL", "DB_URL", false},
		{"*_*", "DB_URL", true},
		{"a*b*c", "aXXbYYc", true},
		{"a*b*c", "aXXbYY", false},
		{"ключ*", "КЛЮЧ_РУ", true}, // сравнение по рунам, не по байтам
	}
	for _, c := range cases {
		if got := matchFilter(c.pat, c.name); got != c.want {
			t.Errorf("matchFilter(%q, %q) = %v, ждали %v", c.pat, c.name, got, c.want)
		}
	}
}

func TestGlobMatchBacktrack(t *testing.T) {
	// звёздочка должна уметь «отдать» символы назад: aab под a*ab
	if !globMatch("a*ab", "aaab") {
		t.Error("глоб не откатился на звёздочку: a*ab не совпал с aaab")
	}
	if globMatch("a*z", "abc") {
		t.Error("хвост шаблона проигнорирован: a*z совпал с abc")
	}
	if !globMatch("abc*", "abc") {
		t.Error("хвостовая звёздочка должна матчить пустой остаток")
	}
}
