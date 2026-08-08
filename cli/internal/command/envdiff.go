package command

// Сверка стора с env-файлом (локальным или на хосте) — общий движок для
// sec diff <proj> <цель> и sec deploy. Значения не раскрываются: сравнение идёт
// по отпечаткам, в вывод попадают только имена и статусы. Исключение —
// kind: config (несекретная настройка): её видеть открытым текстом полезнее,
// чем отпечаток, ради этого вид и заводился.

import (
	"crypto/hmac"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/kaidstor/sec/internal/store"
)

type envStatus int

const (
	envSame    envStatus = iota // значения совпадают
	envDiffer                   // ключ есть с обеих сторон, значения разные
	envMissing                  // есть в сторе, в файле нет
	envExtra                    // есть в файле, в сторе нет
)

type envEntry struct {
	key      string
	status   envStatus
	config   bool   // kind: config — значения можно показывать открыто
	storeVal string // заполнены только у config
	fileVal  string
}

// compareEnvFile сопоставляет ключи проекта с разобранным env-файлом.
// Результат отсортирован по имени ключа.
func compareEnvFile(keys map[string]store.Secret, fileKV map[string]string, mkey []byte) []envEntry {
	seen := map[string]struct{}{}
	for k := range keys {
		seen[k] = struct{}{}
	}
	for k := range fileKV {
		seen[k] = struct{}{}
	}
	out := make([]envEntry, 0, len(seen))
	for _, k := range store.SortedKeys(seen) {
		sec, inStore := keys[k]
		fv, inFile := fileKV[k]
		e := envEntry{key: k, config: inStore && sec.IsConfig()}
		switch {
		case inStore && inFile:
			if hmac.Equal([]byte(store.Fingerprint(mkey, sec.Value)), []byte(store.Fingerprint(mkey, fv))) {
				e.status = envSame
			} else {
				e.status = envDiffer
			}
		case inStore:
			e.status = envMissing
		default:
			e.status = envExtra
		}
		if e.config {
			e.storeVal, e.fileVal = sec.Value, fv
		}
		out = append(out, e)
	}
	return out
}

type envCounts struct{ same, differ, missing, extra int }

func (c envCounts) changed() bool { return c.differ > 0 || c.missing > 0 }

// printEnvDiff печатает сверку и возвращает счётчики. dropExtra=true (deploy
// --replace) меняет смысл строк «только в файле»: они не останутся, а исчезнут.
func printEnvDiff(entries []envEntry, t envTarget, dropExtra bool) envCounts {
	var c envCounts
	where := t.label()
	for _, e := range entries {
		switch e.status {
		case envSame:
			c.same++
			fmt.Printf("= %-32s совпадает\n", e.key)
		case envDiffer:
			c.differ++
			fmt.Printf("~ %-32s различаются%s\n", e.key, configTail(e))
		case envMissing:
			c.missing++
			fmt.Printf("+ %-32s нет %s%s\n", e.key, where, configTail(e))
		case envExtra:
			c.extra++
			if dropExtra {
				fmt.Printf("- %-32s будет удалён (только %s, в сторе нет)\n", e.key, where)
			} else {
				fmt.Printf("? %-32s только %s (в сторе нет)\n", e.key, where)
			}
		}
	}
	tail := fmt.Sprintf("только %s — %d", where, c.extra)
	if dropExtra {
		tail = fmt.Sprintf("будет удалено %s — %d", where, c.extra)
	}
	fmt.Printf("итого: совпадают %d, различаются %d, нет %s — %d, %s\n",
		c.same, c.differ, where, c.missing, tail)
	return c
}

// configTail — хвост строки со значениями для kind: config (для остальных пуст).
func configTail(e envEntry) string {
	if !e.config {
		return ""
	}
	switch e.status {
	case envDiffer:
		return fmt.Sprintf("     стор: %s   файл: %s", oneLine(e.storeVal), oneLine(e.fileVal))
	case envMissing:
		return fmt.Sprintf("     стор: %s", oneLine(e.storeVal))
	}
	return ""
}

// oneLine готовит значение конфига к печати одной строкой рядом с именем ключа.
// Управляющие символы экранируются все, а не только переводы строк: значение
// приезжает из чужого файла на хосте, а сырой ESC в терминале — это уже не
// «показали настройку», а исполнили чужую OSC-последовательность.
func oneLine(v string) string {
	var b strings.Builder
	for _, r := range v {
		switch {
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		default:
			b.WriteRune(r)
		}
	}
	out := b.String()
	if len([]rune(out)) > 60 {
		out = string([]rune(out)[:60]) + "…"
	}
	return out
}

// envKeysOf собирает ключи проекта, годные для env-файла: без бинарных и без
// kind: file (многокилобайтному PEM в .env не место — доставать его get --out),
// с фильтром --only. Пропущенное перечисляется в stderr, как в export.
func envKeysOf(st *store.Store, proj, only string) map[string]store.Secret {
	keys := st.EffectiveKeys(proj) // собственные + унаследованные, ссылки разрешены
	if len(keys) == 0 {
		die("проект %q пуст или не существует (sec ls)", proj)
	}
	if only != "" {
		want := map[string]bool{}
		var missing []string
		for _, k := range strings.Split(only, ",") {
			if k = strings.TrimSpace(k); k == "" {
				continue
			}
			s, ok := keys[k]
			if !ok {
				missing = append(missing, k)
			} else if s.IsFile() {
				// явно названный файловый ключ — точная ошибка здесь, иначе он
				// молча выпадет ниже и команда упадёт «не осталось ключей»
				die("%s/%s — файловый (kind: file) секрет, в env-файл он не пишется: sec get %s/%s --out <файл>",
					proj, k, st.DisplayProj(proj), k)
			}
			want[k] = true
		}
		if len(missing) > 0 {
			die("в проекте %s нет ключей: %s", proj, strings.Join(missing, ", "))
		}
		for k := range keys {
			if !want[k] {
				delete(keys, k)
			}
		}
	}
	var skipped []string
	for k, s := range keys {
		if s.IsFile() { // сюда же попадают бинарные (IsBinary ⊂ IsFile)
			skipped = append(skipped, k)
			delete(keys, k)
		}
	}
	if len(skipped) > 0 {
		sort.Strings(skipped)
		fmt.Fprintf(os.Stderr, "sec: файловые (kind: file) ключи в env-файле не участвуют: %s (доставать: sec get %s/<KEY> --out <файл>)\n",
			strings.Join(skipped, ", "), st.DisplayProj(proj))
	}
	if len(keys) == 0 {
		die("в %s не осталось ключей для env-файла", proj)
	}
	return keys
}
