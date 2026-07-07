package store

import "testing"

// storeWith собирает стор из проектов и связей наследования для тестов резолвера.
func storeWith(projects map[string]map[string]Secret, extends map[string][]string) *Store {
	return &Store{Version: 1, Projects: projects, Extends: extends}
}

func TestResolveSecretChain(t *testing.T) {
	st := storeWith(map[string]map[string]Secret{
		"app":  {"A": {Ref: "base/X"}, "LOOP1": {Ref: "app/LOOP2"}, "LOOP2": {Ref: "app/LOOP1"}, "DEAD": {Ref: "base/GONE"}},
		"base": {"X": {Value: "real"}},
	}, nil)

	// цепочка ссылок доходит до настоящего значения
	sec, src, ok := st.ResolveSecret("app", "A")
	if !ok || sec.Value != "real" || src != "base/X" {
		t.Fatalf("resolveSecret(app/A) = %q, %q, %v; want real, base/X, true", sec.Value, src, ok)
	}
	// собственное значение без ссылки — сразу оно
	if sec, _, ok := st.ResolveSecret("base", "X"); !ok || sec.Value != "real" {
		t.Errorf("resolveSecret(base/X) = %q, %v", sec.Value, ok)
	}
	// битая ссылка — ok=false, source указывает на потерянного родителя
	if _, src, ok := st.ResolveSecret("app", "DEAD"); ok || src != "base/GONE" {
		t.Errorf("resolveSecret(app/DEAD) = _, %q, %v; want _, base/GONE, false", src, ok)
	}
	// цикл упирается в предел глубины и не зависает
	if _, _, ok := st.ResolveSecret("app", "LOOP1"); ok {
		t.Error("циклическая ссылка должна вернуть ok=false")
	}
}

func TestLookupExtendAndOverride(t *testing.T) {
	st := storeWith(map[string]map[string]Secret{
		"app":   {"Y": {Value: "own-y"}, "R": {Ref: "base/X"}},
		"base":  {"X": {Value: "base-x"}, "Y": {Value: "base-y"}},
		"grand": {"G": {Value: "grand-g"}},
	}, map[string][]string{
		"app":  {"base"},
		"base": {"grand"},
	})

	// собственный ключ перекрывает унаследованный
	if sec, org, _, ok := st.Lookup("app", "Y"); !ok || org != OriginOwn || sec.Value != "own-y" {
		t.Errorf("lookup(app/Y) = %q, org=%d, ok=%v; want own-y/own", sec.Value, org, ok)
	}
	// унаследованный из прямого родителя
	if sec, org, src, ok := st.Lookup("app", "X"); !ok || org != OriginExtend || sec.Value != "base-x" || src != "base/X" {
		t.Errorf("lookup(app/X) = %q, org=%d, src=%q, ok=%v; want base-x/extend/base/X", sec.Value, org, src, ok)
	}
	// унаследованный вглубь (дед через родителя)
	if sec, org, _, ok := st.Lookup("app", "G"); !ok || org != OriginExtend || sec.Value != "grand-g" {
		t.Errorf("lookup(app/G) = %q, org=%d, ok=%v; want grand-g/extend", sec.Value, org, ok)
	}
	// собственная ссылка резолвится и помечается как ref
	if sec, org, src, ok := st.Lookup("app", "R"); !ok || org != OriginRef || sec.Value != "base-x" || src != "base/X" {
		t.Errorf("lookup(app/R) = %q, org=%d, src=%q, ok=%v; want base-x/ref/base/X", sec.Value, org, src, ok)
	}
	// несуществующий ключ
	if _, _, _, ok := st.Lookup("app", "NOPE"); ok {
		t.Error("lookup несуществующего ключа должен вернуть ok=false")
	}
}

func TestEffectiveKeysMerge(t *testing.T) {
	st := storeWith(map[string]map[string]Secret{
		"app":  {"Y": {Value: "own-y"}, "Z": {Value: "own-z"}, "R": {Ref: "base/X"}},
		"base": {"X": {Value: "base-x"}, "Y": {Value: "base-y"}},
	}, map[string][]string{"app": {"base"}})

	eff := st.EffectiveKeys("app")
	want := map[string]string{"X": "base-x", "Y": "own-y", "Z": "own-z", "R": "base-x"}
	if len(eff) != len(want) {
		t.Fatalf("effectiveKeys дал %d ключей, ждали %d: %v", len(eff), len(want), eff)
	}
	for k, v := range want {
		if eff[k].Value != v {
			t.Errorf("effectiveKeys[%s] = %q; want %q", k, eff[k].Value, v)
		}
	}
}

func TestExtendCycleAndDedup(t *testing.T) {
	st := storeWith(map[string]map[string]Secret{
		"a": {"K": {Value: "v"}}, "b": {"K": {Value: "v"}}, "c": {"K": {Value: "v"}},
	}, nil)

	if !st.AddExtend("a", "b") {
		t.Fatal("a→b должно добавиться")
	}
	if !st.AddExtend("b", "c") {
		t.Fatal("b→c должно добавиться")
	}
	// прямой цикл
	if st.AddExtend("b", "a") {
		t.Error("b→a создало бы цикл — должно быть отклонено")
	}
	// транзитивный цикл (c уже достигает a через b)
	if st.AddExtend("c", "a") {
		t.Error("c→a (транзитивный цикл) должно быть отклонено")
	}
	// ссылка на себя
	if st.AddExtend("a", "a") {
		t.Error("a→a должно быть отклонено")
	}
	// идемпотентность — повтор не плодит дублей
	if !st.AddExtend("a", "b") || len(st.Extends["a"]) != 1 {
		t.Errorf("повторный addExtend не должен плодить дубли: %v", st.Extends["a"])
	}
	// removeExtend
	if !st.RemoveExtend("a", "b") {
		t.Error("removeExtend должен вернуть true")
	}
	if _, ok := st.Extends["a"]; ok {
		t.Error("после удаления единственного родителя запись должна исчезнуть")
	}
	if st.RemoveExtend("a", "b") {
		t.Error("повторный removeExtend должен вернуть false")
	}
}

func TestReferrersAndExtenders(t *testing.T) {
	st := storeWith(map[string]map[string]Secret{
		"base":  {"X": {Value: "v"}, "Y": {Value: "w"}},
		"app":   {"R": {Ref: "base/X"}, "OWN": {Value: "o"}},
		"other": {"Q": {Ref: "base@prod/X"}, "S": {Ref: "base/Y"}},
	}, map[string][]string{
		"app":   {"base"},
		"child": {"base"},
	})

	// на base/X ссылается только app/R (other/Q целится в base@prod, другой проект)
	if got := st.Referrers("base/X"); len(got) != 1 || got[0] != "app/R" {
		t.Errorf("referrers(base/X) = %v; want [app/R]", got)
	}
	if got := st.Referrers("base/GONE"); len(got) != 0 {
		t.Errorf("referrers несуществующего = %v; want []", got)
	}
	// на любой ключ base ссылаются app/R (→X) и other/S (→Y)
	got := st.ProjectReferrers("base")
	if len(got) != 2 || got[0] != "app/R" || got[1] != "other/S" {
		t.Errorf("projectReferrers(base) = %v; want [app/R other/S]", got)
	}
	// от base наследуют app и child (отсортированы)
	ext := st.Extenders("base")
	if len(ext) != 2 || ext[0] != "app" || ext[1] != "child" {
		t.Errorf("extenders(base) = %v; want [app child]", ext)
	}
	if got := st.Extenders("app"); len(got) != 0 {
		t.Errorf("extenders(app) = %v; want []", got)
	}
}

func TestRefToCLIProj(t *testing.T) {
	if got := RefToCLIProj("svc@prod"); got != "svc -e prod" {
		t.Errorf("RefToCLIProj(svc@prod) = %q", got)
	}
	if got := RefToCLIProj("svc"); got != "svc" {
		t.Errorf("RefToCLIProj(svc) = %q", got)
	}
}

func TestSplitRefAndCLI(t *testing.T) {
	for _, c := range []struct{ in, proj, key string }{
		{"base/X", "base", "X"},
		{"svc@prod/TOKEN", "svc@prod", "TOKEN"},
	} {
		p, k, ok := splitRef(c.in)
		if !ok || p != c.proj || k != c.key {
			t.Errorf("splitRef(%q) = %q, %q, %v", c.in, p, k, ok)
		}
	}
	for _, bad := range []string{"noslash", "/leading", "trailing/"} {
		if _, _, ok := splitRef(bad); ok {
			t.Errorf("splitRef(%q) должен быть невалиден", bad)
		}
	}
	if got := RefToCLI("svc@prod/TOKEN"); got != "svc/TOKEN -e prod" {
		t.Errorf("RefToCLI(svc@prod/TOKEN) = %q", got)
	}
	if got := RefToCLI("svc/TOKEN"); got != "svc/TOKEN" {
		t.Errorf("RefToCLI(svc/TOKEN) = %q", got)
	}
}
