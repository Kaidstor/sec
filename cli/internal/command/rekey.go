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
	"flag"
	"fmt"
	"os"
)

func rekeyCommand(args []string) int {
	fs := flag.NewFlagSet("rekey", flag.ExitOnError)
	_ = fs.Parse(args)

	unlock := store.Lock()
	defer unlock()
	st, oldKey, backend, err := store.Open(false)
	if err != nil {
		die("%v", err)
	}

	newKey := make([]byte, 32)
	if _, err := rand.Read(newKey); err != nil {
		die("rand: %v", err)
	}
	newHex := hex.EncodeToString(newKey)
	oldHex := hex.EncodeToString(oldKey)

	switch backend {
	case "keyring":
		if err := keyring.OSWrite(newHex); err != nil {
			die("не удалось записать новый ключ в системное хранилище: %v", err)
		}
		if err := store.Save(st, newKey); err != nil {
			_ = keyring.OSWrite(oldHex) // откат
			die("перешифровка не удалась, ключ в системном хранилище откачен на прежний: %v", err)
		}
	case "file":
		p := keyring.FilePath()
		if err := os.WriteFile(p, []byte(newHex+"\n"), 0o600); err != nil {
			die("запись ключа %s: %v", p, err)
		}
		if err := store.Save(st, newKey); err != nil {
			_ = os.WriteFile(p, []byte(oldHex+"\n"), 0o600) // откат
			die("перешифровка не удалась, ключ в файле откачен на прежний: %v", err)
		}
	case "env":
		if err := store.Save(st, newKey); err != nil {
			die("перешифровка не удалась (стор не тронут): %v", err)
		}
		fmt.Println("хранилище перешифровано. НОВЫЙ мастер-ключ — обнови SEC_KEY немедленно,")
		fmt.Println("иначе на следующем запуске стор не расшифруется:")
		fmt.Println(newHex)
		audit.Record("rekey", "*", "backend=env")
		return 0
	default:
		die("неизвестный бэкенд ключа %q", backend)
	}

	audit.Record("rekey", "*", "backend="+backend)
	fmt.Printf("мастер-ключ ротирован, хранилище перешифровано (бэкенд: %s)\n", backend)
	fmt.Println("если делал переносной бэкап старым ключом — он по-прежнему открывается своей passphrase")
	return 0
}
