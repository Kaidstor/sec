package command

import "testing"

func TestNormalizeShareURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"share.kaidstor.ru", "https://share.kaidstor.ru"},
		{"https://share.kaidstor.ru/", "https://share.kaidstor.ru"},
		{"http://localhost:8080", "http://localhost:8080"},
		{"  share.kaidstor.ru  ", "https://share.kaidstor.ru"},
	}
	for _, c := range cases {
		if got := normalizeShareURL(c.in); got != c.want {
			t.Errorf("normalizeShareURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestHostOf(t *testing.T) {
	if got := hostOf("https://share.kaidstor.ru"); got != "share.kaidstor.ru" {
		t.Errorf("hostOf = %q", got)
	}
}

// _share намеренно не проходит projRe: пользователь не может задеть служебный
// проект через set/rm/link — тест страхует от «починки» регэкспа.
func TestShareConfigProjectReserved(t *testing.T) {
	if projRe.MatchString(shareConfigProject) {
		t.Fatalf("%q стал валидным именем проекта — служебный конфиг share больше не защищён", shareConfigProject)
	}
}
