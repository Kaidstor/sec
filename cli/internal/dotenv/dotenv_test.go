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

// Спецсимволы в значениях: то, чем реально бывают набиты токены и пароли.
func TestParseSpecialChars(t *testing.T) {
	cases := []struct {
		name, line, key, want string
	}{
		{"равно внутри", `JWT=eyJhbG==.payload==`, "JWT", "eyJhbG==.payload=="},
		{"решётка не комментарий", `PASS=p@ss#word!`, "PASS", "p@ss#word!"},
		{"решётка в кавычках", `PASS="p@ss # word"`, "PASS", "p@ss # word"},
		{"пробелы вокруг =", `KEY = value`, "KEY", "value"},
		{"пробелы сохраняются в кавычках", `KEY="  padded  "`, "KEY", "  padded  "},
		{"голое значение обрезается", "KEY=  value  ", "KEY", "value"},
		{"спецсимволы shell", `PASS=$(whoami)&&echo|ls;<>`, "PASS", "$(whoami)&&echo|ls;<>"},
		{"обратные кавычки", "PASS=`id`", "PASS", "`id`"},
		{"одинарные — литерал", `PASS='\n$VAR\t'`, "PASS", `\n$VAR\t`},
		{"двойные — экранирование", `PASS="a\\b\"c"`, "PASS", `a\b"c`},
		{"CRLF-хвост", "KEY=value\r", "KEY", "value"},
		{"CR внутри кавычек", `KEY="a\rb"`, "KEY", "a\rb"},
		{"юникод и эмодзи", "KEY=пароль-🔐-ok", "KEY", "пароль-🔐-ok"},
		{"кавычка внутри голого", `KEY=it's`, "KEY", "it's"},
		{"незакрытая кавычка — как есть", `KEY="abc`, "KEY", `"abc`},
		{"пустые кавычки", `KEY=""`, "KEY", ""},
		{"только пробел в кавычках", `KEY=" "`, "KEY", " "},
		{"export с кавычками", `export PASS="a b"`, "PASS", "a b"},
		{"URL с паролем", `DSN=postgres://u:p%40ss@host:5432/db?sslmode=require`, "DSN", "postgres://u:p%40ss@host:5432/db?sslmode=require"},
	}
	for _, c := range cases {
		kv, warns := Parse(c.line)
		if len(warns) > 0 {
			t.Errorf("%s: неожиданные предупреждения %v", c.name, warns)
		}
		if got, ok := kv[c.key]; !ok || got != c.want {
			t.Errorf("%s: Parse(%q)[%q] = %q (есть: %v), want %q", c.name, c.line, c.key, got, ok, c.want)
		}
	}
}

// BOM от windows-редакторов не должен съедать первый ключ.
func TestParseBOM(t *testing.T) {
	kv, warns := Parse("\ufeffTOKEN=abc\r\nDB_URL=postgres://x\r\n")
	if kv["TOKEN"] != "abc" {
		t.Errorf("BOM испортил первый ключ: %v (warns %v)", kv, warns)
	}
	if kv["DB_URL"] != "postgres://x" {
		t.Errorf("CRLF испортил значение: %q", kv["DB_URL"])
	}
	if len(warns) > 0 {
		t.Errorf("неожиданные предупреждения: %v", warns)
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
		" ",                        // только пробел
		"  padded  ",               // краевые пробелы
		"\ttab\t",                  // краевые табы
		"trailing-cr\r",            // из файла с CRLF
		"\rleading-cr",             //
		"win\r\nline",              // CRLF внутри значения
		"пароль-🔐-и-юникод",        //
		"nbsp\u00a0",               // неразрывный пробел на краю — TrimSpace режет и его
		"p@ss#word!",               // решётка
		"a=b=c",                    // равно
		"it's",                     // одинарная кавычка
		`\n не перевод строки`,     // литеральные backslash-n
		"eyJhbGciOiJIUzI1NiJ9.e30", // JWT
		"multi\n\nempty\nlines",
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
