//go:build !windows

package store

// Файловая блокировка на unix — flock(2).

import (
	"os"
	"syscall"
)

func flockLock(f *os.File) error   { return syscall.Flock(int(f.Fd()), syscall.LOCK_EX) }
func flockUnlock(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }
