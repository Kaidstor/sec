//go:build darwin

package keyring

// Системное хранилище ключа на macOS — Keychain через /usr/bin/security. ACL
// висит на security, а не на нашем бинаре, поэтому пересборка CLI не вызывает
// повторных запросов доступа. При записи ключ уходит в `security -i` через
// stdin (внутри скрипта) — в argv/ps не светится.

import (
	"fmt"
	"os/exec"
	"strings"
)

func osKeyringAvailable() bool {
	_, err := exec.LookPath("security")
	return err == nil
}

func osKeyringName() string {
	return fmt.Sprintf("macOS Keychain (service=%s, account=master)", keyringService())
}

func osKeyringRead() (string, error) {
	out, err := exec.Command("security", "find-generic-password",
		"-s", keyringService(), "-a", "master", "-w").Output()
	return string(out), err
}

func osKeyringWrite(hexKey string) error {
	cmd := exec.Command("security", "-i")
	cmd.Stdin = strings.NewReader(fmt.Sprintf(
		"add-generic-password -s %q -a master -w %s -U\n", keyringService(), hexKey))
	cmd.Stdout, cmd.Stderr = nil, nil
	return cmd.Run()
}
