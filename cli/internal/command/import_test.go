package command

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLooksLikePath(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "prod.env"), []byte("A=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "whois"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)

	cases := []struct {
		arg  string
		want bool
	}{
		{"", false},
		{"whois", false},         // имя проекта, файла с таким именем нет
		{"some-bot", false},      //
		{".env", true},           // ведущая точка
		{"../.env", true},        //
		{"dir/.env", true},       // слэш
		{"~/secrets/.env", true}, //
		{"prod.env", true},       // валидное имя проекта, но рядом есть такой файл
		{"whois", false},         // каталог с таким именем — всё равно проект
	}
	for _, c := range cases {
		if got := looksLikePath(c.arg); got != c.want {
			t.Errorf("looksLikePath(%q) = %v, want %v", c.arg, got, c.want)
		}
	}
}

func TestLooksLikeJSON(t *testing.T) {
	cases := []struct {
		arg  string
		want bool
	}{
		{`{"KEY":"v"}`, true},
		{"  \n{\"KEY\":\"v\"}", true}, // ведущие пробелы/переводы строк
		{"\ufeff{\"KEY\":\"v\"}", true},
		{"{}", true},
		{"whois", false},
		{"path/to/.env", false},
		{`["a"]`, false}, // массив — не наш формат, разберётся как .env и предупредит
		{"", false},
	}
	for _, c := range cases {
		if got := looksLikeJSON(c.arg); got != c.want {
			t.Errorf("looksLikeJSON(%q) = %v, want %v", c.arg, got, c.want)
		}
	}
}

func TestParseImportFormat(t *testing.T) {
	// формат угадывается по содержимому
	kv, warns := parseImport(`{"db":{"pass":"x"}}`, false)
	if kv["DB_PASS"] != "x" || len(warns) > 0 {
		t.Errorf("JSON не распознан: %v (warns %v)", kv, warns)
	}
	kv, warns = parseImport("A=1\nB=2\n", false)
	if kv["A"] != "1" || kv["B"] != "2" || len(warns) > 0 {
		t.Errorf(".env не распознан: %v (warns %v)", kv, warns)
	}
	// --from-json на .env-тексте — ошибка формата (die), поэтому проверяем
	// только обратное: JSON-текст без флага всё равно разбирается как JSON
	if kv, _ := parseImport("\n\n  {\"A\":\"1\"}", false); kv["A"] != "1" {
		t.Errorf("JSON с ведущими переводами строк не распознан: %v", kv)
	}
}
