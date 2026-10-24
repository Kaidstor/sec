package keyring

// Слот «следующего» ключа для rekey. Связки «бэкенд ключа + стор» атомарно не
// записать, поэтому новый ключ сначала ложится сюда, затем перешифровывается
// стор, и только после его коммита ключ переезжает в основной слот. Сбой на
// любом шаге оставляет стор читаемым: старым ключом из основного слота либо
// новым — отсюда (store пробует этот слот, когда основной не подошёл).
//
//	keyring — отдельная запись системного хранилища (account master-next)
//	file    — файл <ключ>.next рядом с файлом ключа
//	env     — файл envPath (рядом со стором): SEC_KEY сами мы не поменяем

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// SavePending кладёт новый ключ в слот бэкенда и проверяет, что он читается.
func SavePending(backend, hexKey, envPath string) error {
	switch backend {
	case "keyring":
		if err := osKeyringWrite(accountPending, hexKey); err != nil {
			return err
		}
		out, err := osKeyringRead(accountPending)
		if err != nil || strings.TrimSpace(out) != hexKey {
			return errors.New("новый ключ не читается из системного хранилища после записи")
		}
		return nil
	case "file", "env":
		return writeKeyFile(pendingFile(backend, envPath), hexKey)
	}
	return fmt.Errorf("неизвестный бэкенд ключа %q", backend)
}

// LoadPending — ключ из слота; nil без ошибки — слот пуст.
func LoadPending(backend, envPath string) ([]byte, error) {
	var raw string
	switch backend {
	case "keyring":
		if !osKeyringAvailable() {
			return nil, nil
		}
		out, err := osKeyringRead(accountPending)
		if err != nil || strings.TrimSpace(out) == "" {
			return nil, nil
		}
		raw = out
	case "file", "env":
		data, err := os.ReadFile(pendingFile(backend, envPath))
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		raw = string(data)
	default:
		return nil, nil
	}
	return decodeKey(raw, "ключ незавершённого rekey")
}

// ClearPending опустошает слот (после того, как ключ стал основным).
func ClearPending(backend, envPath string) error {
	switch backend {
	case "keyring":
		if out, err := osKeyringRead(accountPending); err != nil || strings.TrimSpace(out) == "" {
			return nil
		}
		return osKeyringDelete(accountPending)
	case "file", "env":
		err := os.Remove(pendingFile(backend, envPath))
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	return nil
}

// PendingLocation — где лежит слот (для сообщений пользователю).
func PendingLocation(backend, envPath string) string {
	if backend == "keyring" {
		return osKeyringName() + ", account " + accountPending
	}
	return pendingFile(backend, envPath)
}

// Promote делает ключ основным в бэкенде keyring/file и проверяет чтение.
// У env основного слота, доступного нам, нет — его меняет пользователь.
func Promote(backend, hexKey string) error {
	switch backend {
	case "keyring":
		if err := osKeyringWrite(accountMaster, hexKey); err != nil {
			return err
		}
		out, err := osKeyringRead(accountMaster)
		if err != nil || strings.TrimSpace(out) != hexKey {
			return errors.New("ключ не читается из системного хранилища после записи")
		}
		return nil
	case "file":
		return writeKeyFile(FilePath(), hexKey)
	case "env":
		return nil
	}
	return fmt.Errorf("неизвестный бэкенд ключа %q", backend)
}

// NewHex — случайный мастер-ключ (32 байта) в hex.
func NewHex() (string, []byte, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return "", nil, err
	}
	return hex.EncodeToString(k), k, nil
}

func pendingFile(backend, envPath string) string {
	if backend == "env" {
		return envPath
	}
	return FilePath() + ".next"
}

// writeKeyFile атомарно пишет ключ 0600: tmp, fsync, rename, fsync каталога.
func writeKeyFile(p, hexKey string) error {
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, filepath.Base(p)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, werr := f.WriteString(hexKey + "\n")
	if werr == nil {
		werr = f.Chmod(0o600)
		if werr != nil && isWindows() {
			werr = nil
		}
	}
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(tmp, p)
	}
	if werr != nil {
		os.Remove(tmp)
		return werr
	}
	if isWindows() {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func isWindows() bool { return runtime.GOOS == "windows" }
