package command

// CLI-хелперы поверх стора: форматирование времени для показа и гейт на прямое
// редактирование ключей-ссылок/унаследованных (со строками-подсказками «sec …»).
// Сама доменная логика (Lookup/Ref/OriginExtend) — в пакете store.

import (
	"fmt"
	"time"

	"github.com/kaidstor/sec/internal/store"
)

// fmtTime показывает RFC3339-таймстемп в человекочитаемом локальном виде.
func fmtTime(ts string) string {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return ts
	}
	return t.Format("02.01.2006 15:04")
}

// editBlock объясняет, почему ключ нельзя редактировать напрямую (ссылка или
// наследование), либо "" если можно (собственное значение или новый ключ).
func editBlock(st *store.Store, proj, key string) string {
	if own, ok := st.Projects[proj][key]; ok {
		if own.Ref != "" {
			return fmt.Sprintf("%s/%s — ссылка на %s.\n"+
				"     Значение живёт в родителе, меняй его там:\n"+
				"       sec set %s\n"+
				"     Отвязать (сделать собственным): sec unlink %s",
				proj, key, own.Ref, store.RefToCLI(own.Ref), store.RefToCLI(proj+"/"+key))
		}
		return "" // собственное значение — правь свободно
	}
	if _, org, source, ok := st.Lookup(proj, key); ok && org == store.OriginExtend {
		return fmt.Sprintf("%s/%s наследуется из пачки-родителя (%s).\n"+
			"     Меняй в родителе:\n"+
			"       sec set %s\n"+
			"     Дать проекту собственное значение: sec set %s --override",
			proj, key, source, store.RefToCLI(source), store.RefToCLI(proj+"/"+key))
	}
	return "" // ключа ещё нет — обычное создание
}

// mustEditable завершает команду с подсказкой, если ключ нельзя менять напрямую.
// override снимает запрет (для set/gen --override).
func mustEditable(st *store.Store, proj, key string, override bool) {
	if override {
		return
	}
	if msg := editBlock(st, proj, key); msg != "" {
		die("%s", msg)
	}
}
