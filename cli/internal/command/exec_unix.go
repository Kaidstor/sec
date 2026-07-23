//go:build !windows

package command

import "syscall"

// execReplace замещает текущий процесс командой (exec(2)) — секреты живут
// только в envp новой программы. При успехе не возвращается.
func execReplace(path string, argv, env []string) (int, error) {
	return 0, syscall.Exec(path, argv, env)
}
