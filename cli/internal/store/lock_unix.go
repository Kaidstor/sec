//go:build !windows

package store

// Файловая блокировка на unix — flock(2); fsync каталога после rename.

import (
	"errors"
	"os"
	"syscall"
)

const isWindows = false

// flockTry — неблокирующая эксклюзивная блокировка; busy=true — держит другой.
func flockTry(f *os.File) (busy bool, err error) {
	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return true, nil
	}
	return false, err
}

func flockUnlock(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
