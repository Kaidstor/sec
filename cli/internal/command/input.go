package command

// Ввод значений: скрытый TTY-ввод / stdin / буфер обмена. Всё без внешних
// Go-зависимостей. Платформенные реализации (echo, буфер обмена) — в
// input_unix.go / input_windows.go, здесь только общие куски.

import (
	"fmt"
	"os"
	"strings"
)

// confirmYes спрашивает подтверждение перед разрушающим действием. Вопрос идёт
// в stderr, ответ читается со stdin; всё, кроме «y»/«yes»/«д»/«да», считается
// отказом. Не-терминальный stdin — тоже отказ: молча согласиться за
// пользователя в пайпе нельзя, для этого есть явный --yes.
func confirmYes(question string) bool {
	if stdinPiped() {
		fmt.Fprintln(os.Stderr, "sec: stdin — не терминал, спросить некого (подтвердить заранее: --yes)")
		return false
	}
	fmt.Fprintf(os.Stderr, "%s [y/N]: ", question)
	ans, err := readLine(os.Stdin)
	if err != nil && ans == "" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(ans)) {
	case "y", "yes", "д", "да":
		return true
	}
	return false
}

// readLine читает по байту, чтобы не забуферизовать лишнего между двумя
// вызовами readHidden (подтверждение значения).
func readLine(f *os.File) (string, error) {
	var b [1]byte
	var out []byte
	for {
		n, err := f.Read(b[:])
		if n > 0 {
			if b[0] == '\n' {
				break
			}
			out = append(out, b[0])
		}
		if err != nil {
			return strings.TrimRight(string(out), "\r"), err
		}
	}
	return strings.TrimRight(string(out), "\r"), nil
}
