//go:build windows

package store

// Файловая блокировка на Windows — LockFileEx/UnlockFileEx (эксклюзивная,
// блокирующая, на первый байт lock-файла).

import (
	"os"

	"golang.org/x/sys/windows"
)

func flockLock(f *os.File) error {
	var ov windows.Overlapped
	return windows.LockFileEx(windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &ov)
}

func flockUnlock(f *os.File) error {
	var ov windows.Overlapped
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &ov)
}
