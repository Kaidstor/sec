//go:build !darwin && !linux

package keyring

// Платформы без интеграции с системным хранилищем ключа (Windows, *BSD и пр.):
// мастер-ключ живёт в env SEC_KEY или файле ~/.config/sec/key (0600). Чтобы
// подключить нативное хранилище (например Windows Credential Manager / DPAPI),
// достаточно добавить keyring_windows.go с тегом `//go:build windows` и этими же
// четырьмя функциями — общую логику в keyring.go трогать не нужно.

import "errors"

func osKeyringAvailable() bool { return false }

func osKeyringName() string {
	return "нет системного хранилища ключа на этой ОС (env SEC_KEY / файл)"
}

func osKeyringRead() (string, error) {
	return "", errors.New("нет системного хранилища ключа на этой ОС")
}

func osKeyringWrite(string) error {
	return errors.New("нет системного хранилища ключа на этой ОС")
}
