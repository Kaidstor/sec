//go:build windows

package command

// На Windows нет exec(2): запускаем дочерний процесс с нужным окружением,
// ждём завершения и возвращаем его код выхода. Ctrl-C консоль раздаёт всей
// группе процессов — сами его игнорируем и даём дочернему завершиться первым.
//
// Отдельный путь для .cmd/.bat: CreateProcess не исполняет batch-файлы
// напрямую (ERROR_BAD_EXE_FORMAT), а npm/pnpm/yarn на Windows — ровно такие
// обёртки. Их запускаем через ComSpec (cmd.exe /d /s /c) с ручной сборкой
// командной строки: у cmd.exe свои правила разбора, стандартное квотирование
// CreateProcess для него небезопасно (класс багов CVE-2024-24576).

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
)

func execReplace(path string, argv, env []string) (int, error) {
	var cmd *exec.Cmd
	if ext := strings.ToLower(filepath.Ext(path)); ext == ".cmd" || ext == ".bat" {
		comspec := os.Getenv("ComSpec")
		if comspec == "" {
			comspec = filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
		}
		line, err := batCommandLine(comspec, path, argv[1:])
		if err != nil {
			return 0, err
		}
		cmd = exec.Command(comspec)
		cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: line} // собранная строка уходит в CreateProcess как есть
	} else {
		cmd = exec.Command(path)
		cmd.Args = argv
	}
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	signal.Ignore(os.Interrupt)
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode(), nil
		}
		return 0, err
	}
	return 0, nil
}

// batCommandLine собирает строку `"cmd.exe" /d /s /c "<script> <args>"`:
// /d — без AutoRun-команд реестра, /s — всё после /c трактуется как одна
// команда во внешних кавычках. Каждый аргумент внутри — в своих кавычках,
// где для cmd.exe инертны пробелы и метасимволы &|<>^().
func batCommandLine(comspec, script string, args []string) (string, error) {
	parts := make([]string, 0, 1+len(args))
	for _, a := range append([]string{script}, args...) {
		q, err := batArg(a)
		if err != nil {
			return "", err
		}
		parts = append(parts, q)
	}
	return fmt.Sprintf(`"%s" /d /s /c "%s"`, comspec, strings.Join(parts, " ")), nil
}

// batArg квотирует аргумент для cmd.exe. Символы, которые cmd раскрывает или
// ломает даже внутри кавычек (%-переменные, !-delayed-expansion, сами кавычки,
// переводы строк, NUL), безопасно передать нельзя — отклоняем с ошибкой,
// чтобы аргумент не ушёл интерпретатору в неожиданном виде.
func batArg(a string) (string, error) {
	if strings.ContainsAny(a, "\x00\r\n\"%!") {
		return "", fmt.Errorf("аргумент %q не передать в .cmd/.bat безопасно (кавычки, %%, !, переводы строк не экранируются для cmd.exe)", a)
	}
	return `"` + a + `"`, nil
}
