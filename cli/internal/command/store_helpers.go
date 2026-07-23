package command

// CLI-хелперы поверх стора: форматирование времени для показа и гейт на прямое
// редактирование ключей-ссылок/унаследованных (со строками-подсказками «sec …»).
// Сама доменная логика (Lookup/Ref/OriginExtend) — в пакете store.

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/kaidstor/sec/internal/store"
)

// writeFile0600 пишет секретное содержимое в файл, гарантируя права 0600 и
// для уже существующего файла: os.WriteFile применяет mode только при
// создании — файл с прежними 0644 остался бы читаемым всем. Права затягиваются
// до записи содержимого. На Windows POSIX-прав нет, ошибка Chmod там не фатальна.
func writeFile0600(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := f.Chmod(0o600); err != nil && runtime.GOOS != "windows" {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// fmtTime показывает RFC3339-таймстемп в человекочитаемом локальном виде.
func fmtTime(ts string) string {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return ts
	}
	return t.Format("02.01.2006 15:04")
}

// keyDetails — несекретная сводка ключа для -l (ls и find): когда обновлён,
// сколько версий в истории, метаданные и пометка просроченной ротации.
func keyDetails(s store.Secret) string {
	out := fmtTime(s.UpdatedAt)
	if n := len(s.History); n > 0 {
		out += fmt.Sprintf("  (+%d в истории)", n)
	}
	var parts []string
	if s.IsBinary() {
		parts = append(parts, "бинарный файл")
	}
	if s.Meta != nil {
		if s.Meta.Kind != "" {
			parts = append(parts, s.Meta.Kind)
		}
		if s.Meta.Filename != "" {
			parts = append(parts, s.Meta.Filename)
		}
		if s.Meta.Note != "" {
			parts = append(parts, s.Meta.Note)
		}
		if due, _, ok := dueAt(s); ok && timeNowAfter(due) {
			parts = append(parts, "ПОРА РОТИРОВАТЬ")
		}
	}
	if len(parts) > 0 {
		out += "  — " + strings.Join(parts, ", ")
	}
	return out
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
