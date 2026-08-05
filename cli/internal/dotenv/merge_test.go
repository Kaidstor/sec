package dotenv

import (
	"strings"
	"testing"
)

func TestMergeKeepsLayout(t *testing.T) {
	orig := "# конфиг whois\nWHOIS_VERSION=1.2.3\n\n# провайдеры\nWHOIS_HISTORY_PROVIDERS=whoxy\nexport REDIS_URL=redis://old\n  INDENTED=old\n"
	out, updated, added := Merge(orig, map[string]string{
		"WHOIS_HISTORY_PROVIDERS": "whoxy,ripe",
		"REDIS_URL":               "redis://new",
		"INDENTED":                "new",
		"NEW_KEY":                 "value",
	})

	want := "# конфиг whois\nWHOIS_VERSION=1.2.3\n\n# провайдеры\nWHOIS_HISTORY_PROVIDERS=whoxy,ripe\nexport REDIS_URL=redis://new\n  INDENTED=new\nNEW_KEY=value\n"
	if out != want {
		t.Errorf("merge:\n%q\nожидалось:\n%q", out, want)
	}
	if strings.Join(updated, ",") != "WHOIS_HISTORY_PROVIDERS,REDIS_URL,INDENTED" {
		t.Errorf("updated = %v", updated)
	}
	if strings.Join(added, ",") != "NEW_KEY" {
		t.Errorf("added = %v", added)
	}
}

// Ключи вне kv не трогаются вовсе — даже если написаны непривычно: deploy
// правит точечно, а не переформатирует чужой файл.
func TestMergeLeavesUntouchedLinesByteForByte(t *testing.T) {
	orig := "ODD  =  '  spaced  '\nKEEP=\"quoted # not a comment\"\nTARGET=old\n"
	out, _, _ := Merge(orig, map[string]string{"TARGET": "new"})
	if !strings.Contains(out, "ODD  =  '  spaced  '\n") || !strings.Contains(out, `KEEP="quoted # not a comment"`) {
		t.Errorf("чужие строки переписаны: %q", out)
	}
	if !strings.Contains(out, "TARGET=new") {
		t.Errorf("целевая строка не обновлена: %q", out)
	}
}

func TestMergeCRLFAndNoFinalNewline(t *testing.T) {
	out, _, _ := Merge("A=1\r\nB=2\r\n", map[string]string{"B": "3"})
	if out != "A=1\r\nB=3\r\n" {
		t.Errorf("CRLF не сохранён: %q", out)
	}

	out, _, added := Merge("A=1\nB=2", map[string]string{"B": "3"})
	if out != "A=1\nB=3" || len(added) != 0 {
		t.Errorf("отсутствие финального перевода строки не сохранено: %q", out)
	}

	out, _, _ = Merge("A=1", map[string]string{"B": "2"})
	if out != "A=1\nB=2\n" {
		t.Errorf("дописанный ключ должен встать на новую строку: %q", out)
	}
}

func TestMergeEmptyAndDuplicates(t *testing.T) {
	out, updated, added := Merge("", map[string]string{"B": "2", "A": "1"})
	if out != "A=1\nB=2\n" || len(updated) != 0 || strings.Join(added, ",") != "A,B" {
		t.Errorf("пустой файл: %q, updated=%v, added=%v", out, updated, added)
	}

	// dotenv-парсеры берут последнее вхождение, но оставленное прежнее выше по
	// файлу сбивает с толку — переписываем оба.
	out, updated, _ = Merge("K=first\nother=x\nK=second\n", map[string]string{"K": "new"})
	if out != "K=new\nother=x\nK=new\n" {
		t.Errorf("дубль ключа переписан не везде: %q", out)
	}
	if len(updated) != 1 {
		t.Errorf("дубль должен считаться одним ключом: %v", updated)
	}
}

func TestMergeQuotesSpecialValuesAndKeepsBOM(t *testing.T) {
	out, _, _ := Merge("\ufeffPASS=old\n", map[string]string{"PASS": `p a$s "s#`})
	if !strings.HasPrefix(out, "\ufeff") {
		t.Errorf("BOM потерян: %q", out)
	}
	kv, warns := Parse(out)
	if len(warns) != 0 {
		t.Errorf("результат merge не разбирается обратно: %v", warns)
	}
	if kv["PASS"] != `p a$s "s#` {
		t.Errorf("значение исказилось при round-trip: %q", kv["PASS"])
	}
}

func TestLineKey(t *testing.T) {
	cases := map[string]string{
		"KEY=value":      "KEY",
		"  export KEY=v": "KEY",
		"KEY = v":        "KEY",
		"# KEY=v":        "",
		"":               "",
		"просто строка":  "",
		"1BAD=v":         "",
		"KEY_2=v":        "KEY_2",
		"KEY":            "",
		"export  KEY=v":  "KEY", // пробелы вокруг имени Parse тоже съедает
	}
	for in, want := range cases {
		got, ok := lineKey(in)
		if want == "" && ok {
			t.Errorf("lineKey(%q) = %q, ожидалось «не пара»", in, got)
		}
		if want != "" && got != want {
			t.Errorf("lineKey(%q) = %q, ожидалось %q", in, got, want)
		}
	}
}

func TestMergeAppendsWithFileTerminator(t *testing.T) {
	out, _, _ := Merge("A=1\r\n", map[string]string{"B": "2"})
	if out != "A=1\r\nB=2\r\n" {
		t.Errorf("дописанная строка должна получить терминатор файла: %q", out)
	}
}

// Многострочные значения диалект не поддерживает, а построчный Merge порвал бы
// их пополам — deploy обязан на таком файле остановиться.
func TestMultilineKeys(t *testing.T) {
	data := "PLAIN=v\nQUOTED=\"one line\"\nPRIVATE_KEY=\"-----BEGIN KEY-----\nMIIEow\n-----END KEY-----\"\nAPOS='開\n"
	got := MultilineKeys(data)
	if strings.Join(got, ",") != "PRIVATE_KEY,APOS" {
		t.Errorf("MultilineKeys = %v", got)
	}
	if got := MultilineKeys("A=1\nB=\"ok\"\n# C=\"нет\n"); len(got) != 0 {
		t.Errorf("на корректном файле находок быть не должно: %v", got)
	}
}
