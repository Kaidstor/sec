//go:build linux

package keyring

// Системное хранилище ключа на Linux — Secret Service (GNOME Keyring / KWallet
// и совместимые) через libsecret'овую утилиту `secret-tool`. Прямой аналог
// macOS Keychain. Значение ключа передаётся `secret-tool store` через stdin —
// в argv/ps не попадает. Если secret-tool не установлен или Secret Service не
// поднят (headless без D-Bus/демона), вызовы падают, и общая логика в
// keyring.go штатно откатывается на env SEC_KEY / файл.

import (
	"fmt"
	"os/exec"
	"strings"
)

func osKeyringAvailable() bool {
	_, err := exec.LookPath("secret-tool")
	return err == nil
}

func osKeyringName() string {
	return fmt.Sprintf("libsecret / Secret Service (secret-tool, service=%s, account=master)", keyringService())
}

func osKeyringRead() (string, error) {
	out, err := exec.Command("secret-tool", "lookup",
		"service", keyringService(), "account", "master").Output()
	return string(out), err
}

func osKeyringWrite(hexKey string) error {
	cmd := exec.Command("secret-tool", "store", "--label=sec master key",
		"service", keyringService(), "account", "master")
	cmd.Stdin = strings.NewReader(hexKey) // значение через stdin, не argv
	cmd.Stdout, cmd.Stderr = nil, nil
	return cmd.Run()
}
