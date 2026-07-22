package dotenv

import "testing"

func TestParseJSONFlat(t *testing.T) {
	kv, warns, err := ParseJSON(`{
	  "DB_PASS": "p@ss#word!",
	  "PORT": 5432,
	  "RATE": 1e9,
	  "DEBUG": false,
	  "private_key": "-----BEGIN KEY-----\nline2\n-----END KEY-----\n",
	  "client-email": "sa@project.iam.example.com"
	}`)
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if len(warns) > 0 {
		t.Errorf("неожиданные предупреждения: %v", warns)
	}
	want := map[string]string{
		"DB_PASS":      "p@ss#word!",
		"PORT":         "5432",
		"RATE":         "1e9", // число как в исходнике, не 1e+09
		"DEBUG":        "false",
		"PRIVATE_KEY":  "-----BEGIN KEY-----\nline2\n-----END KEY-----\n",
		"CLIENT_EMAIL": "sa@project.iam.example.com",
	}
	for k, v := range want {
		if kv[k] != v {
			t.Errorf("kv[%q] = %q, want %q", k, kv[k], v)
		}
	}
	if len(kv) != len(want) {
		t.Errorf("лишние ключи: %v", kv)
	}
}

func TestParseJSONNested(t *testing.T) {
	kv, warns, err := ParseJSON(`{
	  "db": {"host": "localhost", "creds": {"pass": "s3cret"}},
	  "hosts": ["a", "b"],
	  "empty": {},
	  "nothing": null
	}`)
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	want := map[string]string{
		"DB_HOST":       "localhost",
		"DB_CREDS_PASS": "s3cret",
		"HOSTS":         `["a","b"]`, // массив — компактным JSON-текстом
	}
	for k, v := range want {
		if kv[k] != v {
			t.Errorf("kv[%q] = %q, want %q", k, kv[k], v)
		}
	}
	if len(kv) != len(want) {
		t.Errorf("лишние ключи: %v", kv)
	}
	if len(warns) != 1 { // только null
		t.Errorf("ожидалось 1 предупреждение про null, получено %v", warns)
	}
}

func TestParseJSONBadKeys(t *testing.T) {
	kv, warns, err := ParseJSON(`{"2fa": "x", "ключ": "y", "": "z", "ok_key": "v"}`)
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if kv["OK_KEY"] != "v" {
		t.Errorf("годный ключ потерян: %v", kv)
	}
	if len(kv) != 1 {
		t.Errorf("негодные ключи должны быть пропущены, получено %v", kv)
	}
	if len(warns) != 3 {
		t.Errorf("ожидалось 3 предупреждения (2fa, кириллица, пустой), получено %v", warns)
	}
}

func TestParseJSONCollision(t *testing.T) {
	// db.pass и DB_PASS дают одно имя — обход детерминированный (по алфавиту),
	// побеждает последний, про коллизию предупреждаем.
	kv, warns, err := ParseJSON(`{"DB_PASS": "first", "db": {"pass": "second"}}`)
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if kv["DB_PASS"] != "second" {
		t.Errorf(`DB_PASS = %q, ждали "second" (последний по алфавиту путь)`, kv["DB_PASS"])
	}
	if len(warns) != 1 {
		t.Errorf("ожидалось предупреждение о коллизии, получено %v", warns)
	}
}

func TestParseJSONErrors(t *testing.T) {
	for _, src := range []string{
		`["a", "b"]`,  // массив
		`"строка"`,    // скаляр
		`{"KEY": "x"`, // битый JSON
		``,            // пусто
	} {
		if _, _, err := ParseJSON(src); err == nil {
			t.Errorf("ParseJSON(%q): ждали ошибку", src)
		}
	}
}

// Значения не должны портиться: спецсимволы, юникод, краевые пробелы.
func TestParseJSONValuesIntact(t *testing.T) {
	kv, _, err := ParseJSON(`{"A":"  padded  ","B":"a\"b\\c","C":"пароль-🔐","D":"line1\nline2","E":"","F":"$(whoami)#|;"}`)
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	want := map[string]string{
		"A": "  padded  ",
		"B": `a"b\c`,
		"C": "пароль-🔐",
		"D": "line1\nline2",
		"E": "",
		"F": "$(whoami)#|;",
	}
	for k, v := range want {
		if kv[k] != v {
			t.Errorf("kv[%q] = %q, want %q", k, kv[k], v)
		}
	}
}

// JSON → стор → .env → обратно: значения переживают оба формата.
func TestJSONToDotenvRoundtrip(t *testing.T) {
	kv, _, err := ParseJSON(`{"A":"  padded  ","B":"a\"b\\c#","C":"line1\nline2","D":"tail\r"}`)
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	for k, v := range kv {
		line := Line(k, v)
		back, warns := Parse(line)
		if len(warns) > 0 {
			t.Errorf("%s: %q → warns %v", k, line, warns)
		}
		if back[k] != v {
			t.Errorf("roundtrip %s: %q → %q → %q", k, v, line, back[k])
		}
	}
}
