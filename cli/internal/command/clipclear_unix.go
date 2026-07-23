//go:build !windows

package command

import "syscall"

// detachSysProcAttr — атрибуты отсоединённого воркера: своя сессия (setsid),
// переживёт выход родителя и не получит его сигналы.
func detachSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}
