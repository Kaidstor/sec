//go:build !windows

package audit

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// caller — имя родительского процесса (кто дернул sec: zsh, node, claude…).
func caller() string {
	out, err := exec.Command("ps", "-o", "comm=", "-p", strconv.Itoa(os.Getppid())).Output()
	if err != nil {
		return ""
	}
	return filepath.Base(strings.TrimSpace(string(out)))
}
