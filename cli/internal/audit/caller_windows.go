//go:build windows

package audit

import (
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// caller — имя родительского процесса (кто дернул sec: powershell, node,
// claude…) через снимок Toolhelp32; `ps` на Windows нет.
func caller() string {
	ppid := uint32(os.Getppid())
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(snap)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		if pe.ProcessID == ppid {
			return strings.TrimSuffix(windows.UTF16ToString(pe.ExeFile[:]), ".exe")
		}
	}
	return ""
}
