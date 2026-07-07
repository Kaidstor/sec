package infisical

import "testing"

func TestParseExportJSONObject(t *testing.T) {
	m, err := parseExportJSON([]byte(`{"FOO":"bar","BAZ":"qux"}`))
	if err != nil {
		t.Fatal(err)
	}
	if m["FOO"] != "bar" || m["BAZ"] != "qux" || len(m) != 2 {
		t.Errorf("объект разобран неверно: %v", m)
	}
}

func TestParseExportJSONArray(t *testing.T) {
	// запасной формат — массив объектов с key/value полями
	m, err := parseExportJSON([]byte(`[{"secretKey":"FOO","secretValue":"bar"},{"key":"BAZ","value":"qux"}]`))
	if err != nil {
		t.Fatal(err)
	}
	if m["FOO"] != "bar" || m["BAZ"] != "qux" {
		t.Errorf("массив разобран неверно: %v", m)
	}
}

func TestParseExportJSONEdge(t *testing.T) {
	if m, err := parseExportJSON([]byte("  ")); err != nil || len(m) != 0 {
		t.Errorf("пустой ввод должен дать пустую мапу без ошибки, got %v %v", m, err)
	}
	if _, err := parseExportJSON([]byte("не json")); err == nil {
		t.Error("на мусоре ожидалась ошибка")
	}
}

func TestEnvLine(t *testing.T) {
	cases := map[[2]string]string{
		{"K", "simple"}:      "K=simple",
		{"K", "with space"}:  `K="with space"`,
		{"K", `q"uote`}:      `K="q\"uote"`,
		{"K", "back\\slash"}: `K="back\\slash"`,
	}
	for in, want := range cases {
		if got := envLine(in[0], in[1]); got != want {
			t.Errorf("envLine(%q,%q) = %q, want %q", in[0], in[1], got, want)
		}
	}
}
