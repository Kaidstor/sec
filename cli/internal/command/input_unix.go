//go:build !windows

package command

// Unix-реализация скрытого ввода и буфера обмена: echo гасится через stty,
// буфер через pbcopy/pbpaste (wl-copy/xclip на Linux).

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
)

// readHidden читает строку с /dev/tty с выключенным echo. Echo
// восстанавливается и по Ctrl-C.
func readHidden(prompt string) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", errors.New("нет TTY для скрытого ввода — подай значение через stdin или --clipboard")
	}
	defer tty.Close()
	fmt.Fprint(tty, prompt)
	if err := sttyEcho(tty, false); err != nil {
		return "", fmt.Errorf("stty: %w", err)
	}
	restore := func() { _ = sttyEcho(tty, true) }
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		select {
		case <-sig:
			restore()
			fmt.Fprintln(tty)
			os.Exit(130)
		case <-done:
		}
	}()
	line, rerr := readLine(tty)
	close(done)
	signal.Stop(sig)
	restore()
	fmt.Fprintln(tty)
	if rerr != nil && line == "" {
		return "", rerr
	}
	return line, nil
}

func stdinPiped() bool {
	st, err := os.Stdin.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice == 0
}

func sttyEcho(tty *os.File, on bool) error {
	arg := "-echo"
	if on {
		arg = "echo"
	}
	cmd := exec.Command("stty", arg)
	cmd.Stdin = tty
	return cmd.Run()
}

func clipboardRead() (string, error) {
	if runtime.GOOS == "darwin" {
		out, err := exec.Command("pbpaste").Output()
		return string(out), err
	}
	for _, c := range [][]string{{"wl-paste", "--no-newline"}, {"xclip", "-selection", "clipboard", "-o"}} {
		if _, err := exec.LookPath(c[0]); err == nil {
			out, err := exec.Command(c[0], c[1:]...).Output()
			return string(out), err
		}
	}
	return "", errors.New("не найден pbpaste/wl-paste/xclip")
}

// clipboardWrite кладёт значение в буфер обмена. На macOS помечает его
// типом org.nspasteboard.ConcealedType (конвенция nspasteboard.org) —
// менеджеры истории буфера (Raycast, Maccy, Alfred, Paste, …) такие записи
// не сохраняют. Если osascript недоступен — откат на обычный pbcopy.
func clipboardWrite(s string) error {
	var cmd *exec.Cmd
	if runtime.GOOS == "darwin" {
		if err := pasteboardWriteConcealed(s); err == nil {
			return nil
		}
		cmd = exec.Command("pbcopy")
	} else if _, err := exec.LookPath("wl-copy"); err == nil {
		cmd = exec.Command("wl-copy")
	} else if _, err := exec.LookPath("xclip"); err == nil {
		cmd = exec.Command("xclip", "-selection", "clipboard", "-i")
	} else {
		return errors.New("не найден pbcopy/wl-copy/xclip")
	}
	cmd.Stdin = strings.NewReader(s)
	return cmd.Run()
}

// pasteboardWriteConcealed пишет строку в NSPasteboard двумя типами сразу —
// обычным текстовым и org.nspasteboard.ConcealedType. Значение передаётся
// через stdin, в argv osascript попадает только сам скрипт. Пустая строка —
// просто очистка буфера (clearContents).
func pasteboardWriteConcealed(s string) error {
	const js = `ObjC.import("AppKit");
var d = $.NSFileHandle.fileHandleWithStandardInput.readDataToEndOfFile;
var v = $.NSString.alloc.initWithDataEncoding(d, $.NSUTF8StringEncoding);
var pb = $.NSPasteboard.generalPasteboard;
pb.clearContents;
if (v && v.length > 0) {
  if (!pb.setStringForType(v, $.NSPasteboardTypeString)) throw new Error("write failed");
  pb.setStringForType(v, "org.nspasteboard.ConcealedType");
}`
	cmd := exec.Command("/usr/bin/osascript", "-l", "JavaScript", "-e", js)
	cmd.Stdin = strings.NewReader(s)
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run()
}
