//go:build !windows

package command

// Unix-проверка прав файла хранилища для sec doctor: только владелец (0600).

import (
	"fmt"
	"os"
)

// storePermsStatus возвращает строку для отчёта doctor и ok=false, если права
// хранилища шире, чем только-владелец.
func storePermsStatus(path string, fi os.FileInfo) (string, bool) {
	if perm := fi.Mode().Perm(); perm != 0o600 {
		return fmt.Sprintf("права хранилища %o, ожидались 600: chmod 600 %s", perm, path), false
	}
	return "права хранилища 600", true
}
