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
			shown = append(shown, st.DisplayRef(e.addr))
		}
		sort.Slice(others, func(i, j int) bool { return others[i].updatedAt < others[j].updatedAt })
		hint := fmt.Sprintf("значение %s уже есть в %s", st.DisplayRef(self), strings.Join(shown, ", "))
		if cmd := linkHintCmd(st.DisplayRef(self), others); cmd != "" {
			hint += " — вместо копии можно ссылку: " + cmd
		} else {
			hint += " — вместо копии можно ссылку (sec link)"
		}
		hints = append(hints, hint)
	}
	return hints
}

// linkHintCmd собирает копипастную команду sec link на старейшего кандидата в
// родители (он и есть «оригинал»). Адрес родителя — кратчайшей формой: равный
// профиль наследуется от ключа и опускается, чужой — svc@prof, базовый набор
// при ключе с профилем — svc@.
func linkHintCmd(self string, candidates []dupeEntry) string {
	if len(candidates) == 0 {
		return ""
	}
	selfProj, _, _ := strings.Cut(self, "/")
	_, prof := store.BaseAndProfile(selfProj)
	pProj, pKey, _ := strings.Cut(candidates[0].addr, "/")
	pSvc, pProf := store.BaseAndProfile(pProj)
	parent := pProj
	switch {
	case pProf == prof:
		parent = pSvc
	case pProf == "":
		parent = pSvc + "@"
	}
	return "sec link " + self + " " + parent + "/" + pKey + " --force"
}

// printDupeHints — обёртка для команд записи: печатает подсказки в stderr.
func printDupeHints(st *store.Store, mkey []byte, proj string, written ...string) {
	for _, h := range dupeHints(st, mkey, proj, written) {
		fmt.Fprintf(os.Stderr, "sec: %s\n", h)
	}
}
