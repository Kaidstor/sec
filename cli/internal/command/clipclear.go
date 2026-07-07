package command

// Отложенная очистка буфера обмена для `get --clip --clear-after Ns`. Значение
// передаётся детач-воркеру через анонимный stdin-пайп (в argv/ps не светится),
// как и мастер-ключ в keychain -i. Воркер спит и чистит буфер только если тот
// всё ещё содержит наше значение — то, что пользователь скопировал позже, не трогаем.

import (
	"io"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"
)

// spawnClipboardClear запускает отсоединённый процесс, который через seconds
// секунд очистит буфер, если в нём всё ещё лежит val.
func spawnClipboardClear(val string, seconds int) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(self, "__clearclip", strconv.Itoa(seconds))
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} // переживёт выход родителя
	cmd.Stdout, cmd.Stderr = nil, nil
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	_, _ = io.WriteString(stdin, val)
	_ = stdin.Close()
	return nil // не ждём — процесс отсоединён и переживёт нас
}

// clearClipWorker — скрытая подкоманда __clearclip: спит и чистит буфер, если
// значение не сменилось. Значение читает из stdin.
func clearClipWorker(args []string) int {
	if len(args) < 1 {
		return 2
	}
	secs, err := strconv.Atoi(args[0])
	if err != nil || secs < 0 {
		return 2
	}
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return 1
	}
	val := string(data)
	time.Sleep(time.Duration(secs) * time.Second)
	if cur, err := clipboardRead(); err == nil && cur == val {
		_ = clipboardWrite("")
	}
	return 0
}
