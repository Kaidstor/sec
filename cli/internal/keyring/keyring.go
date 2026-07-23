package keyring

// Мастер-ключ ищется по порядку: env SEC_KEY → системное хранилище ОС → файл.
// Реализация системного хранилища вынесена в keyring_<os>.go (build-tagged):
// macOS Keychain (`security`), Linux libsecret (`secret-tool`), Windows
// Credential Manager (advapi32), прочие ОС — заглушка (падаем на файл).
// Добавить бэкенд под новую ОС — отдельный файл keyring_<os>.go с четырьмя
// функциями osKeyring*, общую логику трогать не нужно.

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

// OSWrite записывает hex-ключ в системное хранилище ОС (обёртка над
// build-tagged osKeyringWrite). Нужна ротации ключа (rekey) в слое command.
func OSWrite(hexKey string) error { return osKeyringWrite(hexKey) }

// OSName — человекочитаемое имя системного бэкенда (Keychain/libsecret/…),
// для показа в `sec info`.
func OSName() string { return osKeyringName() }

// keyringService — имя «сервиса» для записи в системном хранилище (атрибут,
// по которому ключ находится). SEC_KEYCHAIN_SERVICE оставлен для совместимости.
func keyringService() string {
	if s := os.Getenv("SEC_KEYRING_SERVICE"); s != "" {
		return s
	}
	if s := os.Getenv("SEC_KEYCHAIN_SERVICE"); s != "" {
		return s
	}
	return "sec"
}

func FilePath() string {
	if p := os.Getenv("SEC_KEY_FILE"); p != "" {
		return p
	}
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" && runtime.GOOS == "windows" {
		base = os.Getenv("APPDATA") // конвенция Windows: конфиг — в roaming AppData
	}
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "sec", "key")
}

func decodeKey(s, src string) ([]byte, error) {
	k, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil || len(k) != 32 {
		return nil, fmt.Errorf("%s: ожидается мастер-ключ из 64 hex-символов (32 байта)", src)
	}
	return k, nil
}

// Load возвращает мастер-ключ и имя бэкенда (env|keyring|file).
// create=true — сгенерировать и сохранить, если ключа ещё нигде нет.
func Load(create bool) ([]byte, string, error) {
	if h := os.Getenv("SEC_KEY"); h != "" {
		k, err := decodeKey(h, "SEC_KEY")
		return k, "env", err
	}
	if osKeyringAvailable() {
		if out, err := osKeyringRead(); err == nil && strings.TrimSpace(out) != "" {
			k, derr := decodeKey(out, "системное хранилище")
			return k, "keyring", derr
		}
	}
	if data, err := os.ReadFile(FilePath()); err == nil {
		k, derr := decodeKey(string(data), FilePath())
		return k, "file", derr
	}
	if !create {
		return nil, "", errors.New("мастер-ключ не найден — хранилище ещё не инициализировано (первый `sec set` создаст его)")
	}

	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, "", err
	}
	hexKey := hex.EncodeToString(k)
	if osKeyringAvailable() {
		if err := osKeyringWrite(hexKey); err == nil {
			if out, rerr := osKeyringRead(); rerr == nil && strings.TrimSpace(out) == hexKey {
				fmt.Fprintf(os.Stderr, "sec: мастер-ключ создан в системном хранилище (%s)\n", osKeyringName())
				return k, "keyring", nil
			}
		}
		fmt.Fprintln(os.Stderr, "sec: системное хранилище ключа недоступно, мастер-ключ будет в файле")
	}
	p := FilePath()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return nil, "", err
	}
	if err := os.WriteFile(p, []byte(hexKey+"\n"), 0o600); err != nil {
		return nil, "", err
	}
	fmt.Fprintf(os.Stderr, "sec: мастер-ключ создан: %s (0600, береги как пароль)\n", p)
	return k, "file", nil
}
