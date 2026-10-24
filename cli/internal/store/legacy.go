package store

// SECSTOR2 — прежний формат: весь стор одним файлом
//
//	"SECSTOR2" + nonce(24) + XChaCha20-Poly1305(переносимый JSON), AAD = magic
//
// Читается без изменений; пишется, пока стор не переведён `sec migrate`, и
// при обратной миграции `sec migrate --to-v2`.

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/chacha20poly1305"
)

const legacyMagic = "SECSTOR2"

func legacyEncrypt(key, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append([]byte(legacyMagic), nonce...)
	return aead.Seal(out, nonce, plaintext, []byte(legacyMagic)), nil
}

func legacyDecrypt(key, data []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	head := len(legacyMagic) + aead.NonceSize()
	if len(data) < head || string(data[:len(legacyMagic)]) != legacyMagic {
		return nil, fmt.Errorf("%s: не похоже на хранилище sec", Path())
	}
	nonce := data[len(legacyMagic):head]
	pt, err := aead.Open(nil, nonce, data[head:], []byte(legacyMagic))
	if err != nil {
		return nil, errBadKey
	}
	return pt, nil
}

var errBadKey = errors.New("не удалось расшифровать хранилище: неверный мастер-ключ или файл повреждён")

func legacyParse(key, data []byte) (*Store, error) {
	pt, err := legacyDecrypt(key, data)
	if err != nil {
		return nil, err
	}
	st, err := ParsePortable(pt)
	if err != nil {
		return nil, fmt.Errorf("хранилище: %w", err)
	}
	return st, nil
}

func legacySeal(st *Store, key []byte) ([]byte, error) {
	pt, err := MarshalPortable(st)
	if err != nil {
		return nil, err
	}
	return legacyEncrypt(key, pt)
}

// writeDurable атомарно заменяет p содержимым data: временный файл рядом,
// fsync, rename, fsync каталога. Ошибка любого шага (в т.ч. нет места) —
// ошибка записи, прежний файл остаётся целым.
func writeDurable(p string, data []byte) error {
	tmp, err := writeNew(filepath.Dir(p), filepath.Base(p)+".*.tmp", data)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		os.Remove(tmp)
		return err
	}
	return syncDir(filepath.Dir(p))
}

// writeNew создаёт новый файл 0600 по шаблону имени и сбрасывает его на диск.
func writeNew(dir, pattern string, data []byte) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return "", err
	}
	name := f.Name()
	fail := func(err error) (string, error) {
		f.Close()
		os.Remove(name)
		return "", err
	}
	if err := f.Chmod(0o600); err != nil && !isWindows {
		return fail(err)
	}
	if _, err := f.Write(data); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		os.Remove(name)
		return "", err
	}
	return name, nil
}
