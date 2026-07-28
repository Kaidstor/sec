package command

// Подсказка «такое значение уже есть» после set/gen/import: свежезаписанные
// ключи сверяются с остальным стором по отпечаткам (значения не раскрываются),
// на совпадение печатается готовая команда sec link. Дубль не запрещается —
// подсказка уходит в stderr и на код выхода не влияет.

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/kaidstor/sec/internal/store"
)

type dupeEntry struct{ addr, updatedAt string }

// dupeHints — по строке на каждое значение из written, уже лежащее в сторе под
// другим адресом. Группа одинаковых значений внутри одной записи (import
// пачкой) даёт одну строку, а не пару зеркальных.
func dupeHints(st *store.Store, mkey []byte, proj string, written []string) []string {
	// Enc входит в ключ группы: текст, совпавший с base64-представлением
	// бинарного файла, — не дубль.
	groups := map[string][]dupeEntry{}
	fpOf := map[string]string{}
	for _, p := range store.SortedKeys(st.Projects) {
		for _, k := range store.SortedKeys(st.Projects[p]) {
			s := st.Projects[p][k]
			if s.Ref != "" {
				continue // у ссылки нет собственного значения
			}
			fp := s.Enc + "\x00" + store.Fingerprint(mkey, s.Value)
			groups[fp] = append(groups[fp], dupeEntry{p + "/" + k, s.UpdatedAt})
			fpOf[p+"/"+k] = fp
		}
	}

	var hints []string
	covered := map[string]bool{}
	sort.Strings(written)
	for _, k := range written {
		self := proj + "/" + k
		if covered[self] {
			continue
		}
		group := groups[fpOf[self]]
		if len(group) < 2 {
			continue
		}
		var others []dupeEntry
		var shown []string
		for _, e := range group {
			covered[e.addr] = true
			if e.addr == self {
				continue
			}
			others = append(others, e)
			shown = append(shown, store.RefToCLI(e.addr))
		}
		sort.Slice(others, func(i, j int) bool { return others[i].updatedAt < others[j].updatedAt })
		hint := fmt.Sprintf("значение %s уже есть в %s", store.RefToCLI(self), strings.Join(shown, ", "))
		if cmd := linkHintCmd(self, others); cmd != "" {
			hint += " — вместо копии можно ссылку: " + cmd
		} else {
			hint += " — вместо копии можно ссылку (sec link)"
		}
		hints = append(hints, hint)
	}
	return hints
}

// linkHintCmd собирает копипастную команду sec link на первого выразимого
// кандидата в родители (candidates отсортированы от старейшего — он и есть
// «оригинал»). "" — команду не выразить: у link нет способа задать родителя
// без инстанса, когда сам ключ с инстансом (--parent-env "" падает обратно
// в инстанс ключа).
func linkHintCmd(self string, candidates []dupeEntry) string {
	svcEnv, key, _ := strings.Cut(self, "/")
	svc, env := store.BaseAndEnv(svcEnv)
	for _, c := range candidates {
		pSvcEnv, pKey, _ := strings.Cut(c.addr, "/")
		pSvc, pEnv := store.BaseAndEnv(pSvcEnv)
		if env != "" && pEnv == "" {
			continue
		}
		cmd := "sec link " + svc + "/" + key
		if env != "" {
			cmd += " -e " + env
		}
		cmd += " " + pSvc + "/" + pKey
		if pEnv != "" && pEnv != env {
			cmd += " --parent-env " + pEnv
		}
		return cmd + " --force"
	}
	return ""
}

// printDupeHints — обёртка для команд записи: печатает подсказки в stderr.
func printDupeHints(st *store.Store, mkey []byte, proj string, written ...string) {
	for _, h := range dupeHints(st, mkey, proj, written) {
		fmt.Fprintf(os.Stderr, "sec: %s\n", h)
	}
}
