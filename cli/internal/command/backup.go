package command

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/kaidstor/sec/internal/audit"
	"github.com/kaidstor/sec/internal/backup"
	"github.com/kaidstor/sec/internal/store"
)

// Команды backup/restore: сериализуют стор и запечатывают его переносным
// блобом под passphrase. Крипто (Argon2id + XChaCha20) — в пакете
// internal/backup (backup.Seal / backup.Open); здесь только ввод passphrase,
// работа со стором и вывод.

// readPassphrase: env SEC_PASSPHRASE (для CI/скриптов) либо скрытый ввод.
func readPassphrase(confirm bool) (string, error) {
	if p := os.Getenv("SEC_PASSPHRASE"); p != "" {
		return p, nil
	}
	p1, err := readHidden("passphrase: ")
	if err != nil {
		return "", err
	}
	if len(p1) < 12 {
		return "", errors.New("passphrase короче 12 символов")
	}
	if confirm {
		p2, err := readHidden("повтори: ")
		if err != nil {
			return "", err
		}
		if p1 != p2 {
			return "", errors.New("passphrase не совпали")
		}
	}
	return p1, nil
}

func backupCommand(args []string) int {
	fs := flag.NewFlagSet("backup", flag.ExitOnError)
	var file string
	fs.StringVar(&file, "file", "", "куда записать бэкап (обязателен)")
	_ = fs.Parse(args)
	if file == "" {
		die("укажи файл: sec backup --file sec-backup.enc")
	}

	st, _, _, err := store.Open(false)
	if err != nil {
		die("%v", err)
	}
	pass, err := readPassphrase(true)
	if err != nil {
		die("%v", err)
	}
	pt, err := json.Marshal(st)
	if err != nil {
		die("%v", err)
	}
	blob, err := backup.Seal(pt, pass)
	if err != nil {
		die("%v", err)
	}
	if err := os.WriteFile(file, blob, 0o600); err != nil {
		die("запись %s: %v", file, err)
	}
	total := 0
	for _, keys := range st.Projects {
		total += len(keys)
	}
	audit.Record("backup", "*", "→ "+file)
	fmt.Printf("бэкап записан: %s (%d проектов, %d ключей)\n", file, len(st.Projects), total)
	fmt.Println("восстановление на другой машине: sec restore --file " + file)
	return 0
}

func restoreCommand(args []string) int {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	var file string
	var replace bool
	fs.StringVar(&file, "file", "", "файл бэкапа (обязателен)")
	fs.BoolVar(&replace, "replace", false, "заменить хранилище целиком (по умолчанию — merge)")
	_ = fs.Parse(args)
	if file == "" {
		die("укажи файл: sec restore --file sec-backup.enc")
	}

	data, err := os.ReadFile(file)
	if err != nil {
		die("чтение %s: %v", file, err)
	}
	pass, err := readPassphrase(false)
	if err != nil {
		die("%v", err)
	}
	pt, err := backup.Open(data, pass)
	if err != nil {
		die("%v", err)
	}
	var bak store.Store
	if err := json.Unmarshal(pt, &bak); err != nil {
		die("бэкап повреждён: %v", err)
	}
	if bak.Projects == nil {
		bak.Projects = map[string]map[string]store.Secret{}
	}

	unlock := store.Lock()
	defer unlock()
	st, mkey, _, err := store.Open(true)
	if err != nil {
		die("%v", err)
	}
	mode := "merge"
	added, updated := 0, 0
	if replace {
		mode = "replace"
		st.Projects = bak.Projects
		st.Extends = bak.Extends // наследование пачек — часть стора, переносим вместе
		for _, keys := range bak.Projects {
			added += len(keys)
		}
	} else {
		// merge: значения из бэкапа побеждают, локальные уходят в историю
		added, updated = store.Merge(st, &bak)
	}
	if err := store.Save(st, mkey); err != nil {
		die("запись хранилища: %v", err)
	}
	audit.Record("restore", "*", fmt.Sprintf("из %s (%s)", file, mode))
	if replace {
		fmt.Printf("хранилище заменено из %s (%d ключей)\n", file, added)
	} else {
		fmt.Printf("восстановлено из %s: новых %d, обновлено %d (старые значения в истории)\n", file, added, updated)
	}
	return 0
}
