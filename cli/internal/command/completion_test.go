package command

import (
	"testing"

	"github.com/kaidstor/sec/internal/store"
)

func hasCand(cands []string, want string) bool {
	for _, c := range cands {
		if c == want {
			return true
		}
	}
	return false
}

func completionTestStore() *store.Store {
	return &store.Store{Version: 1, Projects: map[string]map[string]store.Secret{
		"whois":               {"API_TOKEN": {Value: "x"}, "DB_URL": {Value: "y"}},
		"some-bot@commercial": {"BOT_TOKEN": {Value: "z"}},
		"some-bot@max":        {"BOT_TOKEN": {Value: "w"}, "COMPANY_ID": {Value: "c"}},
	}}
}

func TestCompleteSubcommands(t *testing.T) {
	got := completeCandidates(nil, []string{"re"})
	for _, want := range []string{"redact", "render", "redo", "restore", "rekey"} {
		if !hasCand(got, want) {
			t.Errorf("подкоманда %q не предложена: %v", want, got)
		}
	}
	// скрытые команды не должны утекать в дополнение
	for _, bad := range []string{"__complete", "__clearclip"} {
		if hasCand(completeCandidates(nil, []string{"__"}), bad) {
			t.Errorf("скрытая команда %q попала в дополнение", bad)
		}
	}
}

func TestCompleteProject(t *testing.T) {
	st := completionTestStore()
	got := completeCandidates(st, []string{"run", ""})
	if !hasCand(got, "whois") || !hasCand(got, "some-bot") {
		t.Errorf("проекты не предложены: %v", got)
	}
	got = completeCandidates(st, []string{"run", "wh"})
	if !hasCand(got, "whois") || hasCand(got, "some-bot") {
		t.Errorf("префикс проекта не отфильтровал: %v", got)
	}
}

func TestCompleteRef(t *testing.T) {
	st := completionTestStore()
	// часть-проект → имя со слэшем
	if got := completeCandidates(st, []string{"get", "wh"}); !hasCand(got, "whois/") {
		t.Errorf("проект-ссылка не предложена: %v", got)
	}
	// ключи после слэша
	got := completeCandidates(st, []string{"get", "whois/"})
	if !hasCand(got, "whois/API_TOKEN") || !hasCand(got, "whois/DB_URL") {
		t.Errorf("ключи не предложены: %v", got)
	}
	// фильтр по префиксу ключа
	got = completeCandidates(st, []string{"get", "whois/AP"})
	if !hasCand(got, "whois/API_TOKEN") || hasCand(got, "whois/DB_URL") {
		t.Errorf("префикс ключа не отфильтровал: %v", got)
	}
	// ключи инстансов доступны по базовому имени (объединение commercial+max)
	got = completeCandidates(st, []string{"get", "some-bot/"})
	if !hasCand(got, "some-bot/BOT_TOKEN") || !hasCand(got, "some-bot/COMPANY_ID") {
		t.Errorf("ключи инстансов не объединены: %v", got)
	}
}

func TestCompleteEnvAndFlags(t *testing.T) {
	st := completionTestStore()
	// значение -e → инстансы
	if got := completeCandidates(st, []string{"get", "some-bot/BOT_TOKEN", "-e", ""}); !hasCand(got, "commercial") || !hasCand(got, "max") {
		t.Errorf("инстансы не предложены после -e: %v", got)
	}
	// флаги команды
	if got := completeCandidates(st, []string{"get", "whois/API_TOKEN", "--"}); !hasCand(got, "--clip") || !hasCand(got, "--fingerprint") {
		t.Errorf("флаги get не предложены: %v", got)
	}
	// алиас команды классифицируется как канон (list → ls, проектная команда)
	if got := completeCandidates(st, []string{"list", "wh"}); !hasCand(got, "whois") {
		t.Errorf("алиас list не дополняет проекты: %v", got)
	}
}

func TestCompleteFiles(t *testing.T) {
	st := completionTestStore()
	if got := completeCandidates(st, []string{"scan", "some"}); len(got) != 1 || got[0] != "__files__" {
		t.Errorf("для файловой команды ждали __files__, got %v", got)
	}
}

func TestCompleteNilStore(t *testing.T) {
	// без стора proj/KEY пусто, но подкоманды и флаги всё равно работают
	if got := completeCandidates(nil, []string{"get", "whois/"}); len(got) != 0 {
		t.Errorf("без стора ключи должны быть пусты: %v", got)
	}
	if got := completeCandidates(nil, []string{"get", "--"}); !hasCand(got, "--clip") {
		t.Errorf("флаги должны работать без стора: %v", got)
	}
}
