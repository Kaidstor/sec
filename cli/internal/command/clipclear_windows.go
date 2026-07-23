//go:build windows

package command

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// detachSysProcAttr — атрибуты отсоединённого воркера: без своей консоли
// (DETACHED_PROCESS), в отдельной process group (не получит Ctrl-C родителя),
// переживёт закрытие родительского окна.
func detachSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP,
		HideWindow:    true,
	}
}
