package command

// Ввод значений: скрытый TTY-ввод / stdin / буфер обмена. Всё без внешних
// Go-зависимостей. Платформенные реализации (echo, буфер обмена) — в
// input_unix.go / input_windows.go, здесь только общие куски.

import (
	"os"
	"strings"
)

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
