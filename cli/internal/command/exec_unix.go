//go:build !windows

package command

import (
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

// execReplace замещает текущий процесс командой (exec(2)) — секреты живут
// только в envp новой программы. При успехе не возвращается.
func execReplace(path string, argv, env []string) (int, error) {
	return 0, syscall.Exec(path, argv, env)
}

// execSpawn запускает команду дочерним процессом и ждёт её (для run --file:
// после exec(2) некому было бы удалить материализованные файлы). Ctrl-C
// терминал раздаёт всей foreground-группе — ребёнок получает SIGINT сам, а мы
// его игнорируем и доживаём до очистки; TERM/HUP, адресованные одному sec
// (kill, закрытие сессии), пересылаем ребёнку и тоже ждём его выхода.
func execSpawn(path string, argv, env []string) (int, error) {
	cmd := exec.Command(path)
	cmd.Args = argv
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	signal.Ignore(os.Interrupt)
	fwd := make(chan os.Signal, 4)
	signal.Notify(fwd, syscall.SIGTERM, syscall.SIGHUP)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case s := <-fwd:
				_ = cmd.Process.Signal(s)
			case <-done:
				return
			}
		}
	}()
	err := cmd.Wait()
	close(done)
	signal.Stop(fwd)
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode(), nil
		}
		return 0, err
	}
	return 0, nil
}
