//go:build windows

package store

// Файловая блокировка на Windows — LockFileEx/UnlockFileEx (эксклюзивная, на
// первый байт lock-файла). Каталог на Windows не fsync-ается: открыть каталог
// для FlushFileBuffers штатно нельзя.

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

const isWindows = true

func flockTry(f *os.File) (busy bool, err error) {
	var ov windows.Overlapped
	err = windows.LockFileEx(windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &ov)
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) || errors.Is(err, windows.ERROR_IO_PENDING) {
		return true, nil
	}
	return false, err
}

func flockUnlock(f *os.File) error {
	var ov windows.Overlapped
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &ov)
}

func syncDir(string) error { return nil }
