package command

// Синхронизация через общий passphrase-блоб: pull-merge из блоба, затем push
// локального стора обратно. Блоб — тот же переносной формат, что и backup
// (Argon2id + XChaCha20), поэтому его можно держать в Dropbox/iCloud/на сетевом
// диске или пушить в git-обёрткой. Мастер-ключ (Keychain) для блоба не нужен.
//
//	sec sync --file ~/Dropbox/sec.enc
//
// Конфликтов «построчно» нет: значения из блоба вливаются в локальный стор
// как merge (локальные вытесненные значения уходят в историю), потом сводный
// результат пишется обратно в блоб — обе стороны сходятся к объединению.

import (
	"github.com/kaidstor/sec/internal/audit"
	"github.com/kaidstor/sec/internal/backup"
	"github.com/kaidstor/sec/internal/store"

	"encoding/json"
	"fmt"
	"os"
)

func syncCommand(args []string) int {
	fs := newFlagSet("sync")
	var file string
	fs.StringVar(&file, "file", "", "общий зашифрованный блоб (обязателен)")
	_ = fs.Parse(args)
	if file == "" {
		die("укажи общий файл: sec sync --file ~/Dropbox/sec.enc")
	}

	blob, readErr := os.ReadFile(file)
	fresh := os.IsNotExist(readErr)
	if readErr != nil && !fresh {
		dieK(kindIO, "чтение %s: %v", file, readErr)
	}

	pass, err := readPassphrase(fresh) // при первом создании — с подтверждением
	if err != nil {
		die("%v", err)
	}

	unlock := store.Lock()
	defer unlock()
	st, mkey, _, err := store.Open(true)
	if err != nil {
		dieStore(err)
	}

	added, updated := 0, 0
	if !fresh {
		pt, err := backup.Open(blob, pass)
		if err != nil {
			dieK(kindAuth, "%v", err)
		}
		var remote store.Store
		if err := json.Unmarshal(pt, &remote); err != nil {
			dieK(kindIO, "блоб повреждён: %v", err)
		}
		if remote.Projects == nil {
			remote.Projects = map[string]map[string]store.Secret{}
		}
		added, updated = store.Merge(st, &remote)
		if err := store.Save(st, mkey); err != nil {
			dieK(kindStore, "запись локального хранилища: %v", err)
		}
	}

	// push: сводный локальный стор обратно в блоб (атомарно)
	pt, err := json.Marshal(st)
	if err != nil {
		dieK(kindStore, "%v", err)
	}
	sealed, err := backup.Seal(pt, pass)
	if err != nil {
		dieK(kindStore, "%v", err)
	}
	tmp := file + ".tmp"
	if err := os.WriteFile(tmp, sealed, 0o600); err != nil {
		dieK(kindIO, "запись %s: %v", tmp, err)
	}
	if err := os.Rename(tmp, file); err != nil {
		dieK(kindIO, "замена %s: %v", file, err)
	}

	audit.Record("sync", "*", "↔ "+file)
	if fresh {
		fmt.Fprintf(stdout, "создан общий блоб %s из локального стора\n", file)
	} else {
		fmt.Fprintf(stdout, "синхронизировано с %s: подтянуто новых %d, обновлено %d, отправлен сводный стор\n", file, added, updated)
	}
	emit(map[string]any{"file": file, "created": fresh, "added": added, "updated": updated})
	return 0
}
