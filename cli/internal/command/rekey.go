package command

// Ротация мастер-ключа: генерирует новый ключ и перешифровывает хранилище.
// Значения секретов сохраняются. Порядок с откатом: сначала обновляем бэкенд
// ключа, затем перешифровываем стор; если перешифровка сорвалась — возвращаем
// прежний ключ в бэкенд, чтобы стор остался читаемым.

import (
	"github.com/kaidstor/sec/internal/audit"
	"github.com/kaidstor/sec/internal/keyring"
	"github.com/kaidstor/sec/internal/store"

	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
)

func rekeyCommand(args []string) int {
	fs := newFlagSet("rekey")
	_ = fs.Parse(args)

	unlock := store.Lock()
	defer unlock()
	st, oldKey, backend, err := store.Open(false)
	if err != nil {
		dieStore(err)
	}

	// с бэкендом env новый ключ печатается один раз и больше нигде не живёт:
	// в конверт он не кладётся (секрет в JSON — только у get), а потерять его
	// значит потерять стор — отказываем до ротации
	if backend == "env" && jsonMode {
		return fail(2, kindUsage, "с мастер-ключом из SEC_KEY новый ключ печатается один раз — запусти sec rekey без --json")
	}

	newKey := make([]byte, 32)
	if _, err := rand.Read(newKey); err != nil {
		dieK(kindIO, "rand: %v", err)
	}
	newHex := hex.EncodeToString(newKey)
	oldHex := hex.EncodeToString(oldKey)

	switch backend {
	case "keyring":
		if err := keyring.OSWrite(newHex); err != nil {
			dieK(kindStore, "не удалось записать новый ключ в системное хранилище: %v", err)
		}
		if err := store.Save(st, newKey); err != nil {
			_ = keyring.OSWrite(oldHex) // откат
			dieK(kindStore, "перешифровка не удалась, ключ в системном хранилище откачен на прежний: %v", err)
		}
	case "file":
		p := keyring.FilePath()
		if err := os.WriteFile(p, []byte(newHex+"\n"), 0o600); err != nil {
			dieK(kindIO, "запись ключа %s: %v", p, err)
		}
		if err := store.Save(st, newKey); err != nil {
			_ = os.WriteFile(p, []byte(oldHex+"\n"), 0o600) // откат
			dieK(kindStore, "перешифровка не удалась, ключ в файле откачен на прежний: %v", err)
		}
	case "env":
		if err := store.Save(st, newKey); err != nil {
			dieK(kindStore, "перешифровка не удалась (стор не тронут): %v", err)
		}
		fmt.Fprintln(stdout, "хранилище перешифровано. НОВЫЙ мастер-ключ — обнови SEC_KEY немедленно,")
		fmt.Fprintln(stdout, "иначе на следующем запуске стор не расшифруется:")
		fmt.Fprintln(stdout, newHex)
		audit.Record("rekey", "*", "backend=env")
		return 0
	default:
		dieK(kindConfig, "неизвестный бэкенд ключа %q", backend)
	}

	audit.Record("rekey", "*", "backend="+backend)
	fmt.Fprintf(stdout, "мастер-ключ ротирован, хранилище перешифровано (бэкенд: %s)\n", backend)
	fmt.Fprintln(stdout, "если делал переносной бэкап старым ключом — он по-прежнему открывается своей passphrase")
	emit(map[string]any{"backend": backend})
	return 0
}
