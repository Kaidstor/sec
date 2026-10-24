package store

// Перевод стора между форматами под блокировкой записи (той же, что берут
// старые бинари). Порядок для обоих направлений: новый файл собирается рядом,
// перечитывается и сверяется с исходной логической моделью байт-в-байт
// (канонический переносимый JSON: значения, история, redo, enc, даты, мета,
// ссылки, наследование), сбрасывается на диск и одним rename встаёт на место.
// Сбой до rename оставляет прежний стор нетронутым, после — полностью новый.

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// MigrateResult — что сделала миграция (без значений и контрольных сумм).
type MigrateResult struct {
	From, To string
	Projects int
	Keys     int
	Values   int    // значений с историей и redo
	Backup   string // зашифрованная копия прежнего SECSTOR2 (только v2 → v3)
}

func counts(st *Store) (projects, keys, values int) {
	for _, ks := range st.Projects {
		projects++
		for _, s := range ks {
			keys++
			values += 1 + len(s.History) + len(s.RedoStack)
		}
	}
	return
}

// Migrate переводит SECSTOR2 в SQLite. Прежний файл сохраняется байт-в-байт
// рядом (<стор>.v2-<время>.bak, он уже зашифрован мастер-ключом).
func Migrate() (MigrateResult, error) {
	st, key, _, err := Begin(false)
	if err != nil {
		return MigrateResult{}, err
	}
	defer st.Close()
	res := MigrateResult{From: st.Format(), To: "v3"}
	res.Projects, res.Keys, res.Values = counts(st)
	switch st.Format() {
	case "v3":
		return res, nil
	case "none":
		return res, errors.New("хранилища ещё нет — первый sec set создаст его сразу в новом формате")
	}
	p, orig := st.sess.path, st.sess.raw
	tmp, err := buildSQLite(p, st, key)
	if err != nil {
		return res, fmt.Errorf("сборка новой базы: %w", err)
	}
	keepTmp := false
	defer func() {
		if !keepTmp {
			removeDB(tmp)
		}
	}()
	hook("migrate:built")
	if err := verifySQLite(tmp, key, st); err != nil {
		return res, err
	}
	bak, err := writeBackup(p, orig)
	if err != nil {
		return res, fmt.Errorf("копия прежнего стора: %w", err)
	}
	res.Backup = bak
	hook("migrate:backup")
	if err := installDB(tmp, p); err != nil {
		return res, fmt.Errorf("замена стора: %w", err)
	}
	keepTmp = true
	hook("migrate:installed")
	return res, nil
}

// MigrateToV2 возвращает SQLite-стор в SECSTOR2 (для отката на старый бинарь)
// со всеми текущими данными, включая записанные после перехода.
func MigrateToV2() (MigrateResult, error) {
	st, key, _, err := Begin(false)
	if err != nil {
		return MigrateResult{}, err
	}
	defer st.Close()
	res := MigrateResult{From: st.Format(), To: "v2"}
	res.Projects, res.Keys, res.Values = counts(st)
	switch st.Format() {
	case "v2":
		return res, nil
	case "none":
		return res, errors.New("хранилища нет — переводить нечего")
	}
	p := st.sess.path
	data, err := legacySeal(st, key)
	if err != nil {
		return res, err
	}
	back, err := legacyParse(key, data)
	if err != nil {
		return res, fmt.Errorf("проверка SECSTOR2: %w", err)
	}
	if same, err := samePortable(st, back); err != nil {
		return res, fmt.Errorf("проверка SECSTOR2: %w", err)
	} else if !same {
		return res, errors.New("проверка SECSTOR2 не сошлась с текущим стором — ничего не изменено")
	}
	tmp, err := writeNew(filepath.Dir(p), filepath.Base(p)+".v2-*.tmp", data)
	if err != nil {
		return res, err
	}
	if disk, err := os.ReadFile(tmp); err != nil || !bytes.Equal(disk, data) {
		os.Remove(tmp)
		return res, errors.New("перечитанный с диска SECSTOR2 не совпал с записанным — ничего не изменено")
	}
	// снимок и транзакция закрываются до rename: последнее закрытие вливает WAL,
	// а держать базу открытой под чужим именем незачем; блокировку держим
	lock := st.sess.lock
	st.sess.lock = nil
	defer func() {
		_ = flockUnlock(lock)
		lock.Close()
	}()
	st.Close()
	hook("downgrade:staged")
	if err := os.Rename(tmp, p); err != nil {
		os.Remove(tmp)
		return res, fmt.Errorf("замена стора: %w", err)
	}
	if err := syncDir(filepath.Dir(p)); err != nil {
		return res, err
	}
	// -wal/-shm прежней базы больше не относятся к файлу на этом пути
	return res, removeSidecars(p)
}

// verifySQLite открывает собранную базу отдельным соединением и сверяет её
// логическую модель с исходной, читая все payload.
func verifySQLite(p string, key []byte, want *Store) error {
	d, err := openSQL(p, false)
	if err != nil {
		return err
	}
	defer d.close()
	if err := d.begin(false); err != nil {
		return err
	}
	got, err := d.readCatalog(key)
	if err != nil {
		return fmt.Errorf("проверка новой базы: %w", err)
	}
	same, err := samePortable(want, got)
	if err != nil {
		return fmt.Errorf("проверка новой базы: %w", err)
	}
	if !same {
		return errors.New("новая база не совпала с исходным стором — ничего не изменено")
	}
	return nil
}

// writeBackup кладёт копию прежнего файла рядом, не перезаписывая
// существующие копии.
func writeBackup(p string, data []byte) (string, error) {
	name := fmt.Sprintf("%s.v2-%s.bak", p, time.Now().UTC().Format("20060102T150405.000000000Z"))
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(name)
		return "", err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(name)
		return "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(name)
		return "", err
	}
	return name, syncDir(filepath.Dir(p))
}

// RekeyTo — Commit перешифрует весь стор ключом newKey (каталог и каждое
// значение — новые payload, старые удаляются той же транзакцией). После
// такого Commit блокировка записи держится до Close: обновление ключа в
// бэкенде и очистка слота идут под ней.
func (st *Store) RekeyTo(newKey []byte) error {
	if st.sess == nil || !st.sess.write {
		return errors.New("rekey требует транзакцию записи (внутренняя ошибка sec)")
	}
	st.sess.rekeyTo = newKey
	return nil
}

// PendingKeyPath — файл слота rekey для бэкенда env (рядом со стором).
func PendingKeyPath() string { return Path() + ".rekey-key" }
