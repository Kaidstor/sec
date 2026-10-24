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

func osKeyringRead(account string) (string, error) {
	out, err := exec.Command("secret-tool", "lookup",
		"service", keyringService(), "account", account).Output()
	return string(out), err
}

func osKeyringDelete(account string) error {
	return exec.Command("secret-tool", "clear",
		"service", keyringService(), "account", account).Run()
}

func osKeyringWrite(account, hexKey string) error {
	cmd := exec.Command("secret-tool", "store", "--label=sec "+account+" key",
		"service", keyringService(), "account", account)
	cmd.Stdin = strings.NewReader(hexKey) // значение через stdin, не argv
	cmd.Stdout, cmd.Stderr = nil, nil
	return cmd.Run()
}
