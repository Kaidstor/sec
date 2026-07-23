//go:build windows

package command

// Windows-реализация скрытого ввода и буфера обмена. Echo гасится через
// консольный режим (SetConsoleMode на CONIN$), буфер обмена — нативный Win32
// (user32/kernel32), без внешних процессов: значение не попадает в argv.
// При записи буфер помечается форматами ExcludeClipboardContentFromMonitor-
// Processing / CanIncludeInClipboardHistory=0 / CanUploadToCloudClipboard=0 —
// история Win+V и облачная синхронизация такие записи не сохраняют (аналог
// org.nspasteboard.ConcealedType на macOS).

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// stdinPiped — в stdin действительно подали данные пайпом/редиректом.
// Интерактивный stdin в Git Bash / mintty — это именованный пайп MSYS-pty,
// а не char device: считать его пайпом нельзя, иначе set/verify уйдут в
// io.ReadAll(os.Stdin) и набранный секрет отобразится на экране открытым текстом.
func stdinPiped() bool {
	st, err := os.Stdin.Stat()
	if err != nil || st.Mode()&os.ModeCharDevice != 0 {
		return false
	}
	return !isMsysPty(windows.Handle(os.Stdin.Fd()))
}

// isMsysPty — хэндл является интерактивным pty MSYS/Cygwin (mintty): именованный
// пайп вида \msys-XXXX-ptyN-from-master / \cygwin-XXXX-ptyN-…
func isMsysPty(h windows.Handle) bool {
	if t, err := windows.GetFileType(h); err != nil || t != windows.FILE_TYPE_PIPE {
		return false
	}
	var buf [1024]byte // FILE_NAME_INFO: DWORD FileNameLength + WCHAR FileName[]
	if err := windows.GetFileInformationByHandleEx(h, windows.FileNameInfo, &buf[0], uint32(len(buf))); err != nil {
		return false
	}
	n := binary.LittleEndian.Uint32(buf[0:4])
	if n > uint32(len(buf)-4) {
		n = uint32(len(buf) - 4)
	}
	name := strings.ToLower(windows.UTF16ToString(unsafe.Slice((*uint16)(unsafe.Pointer(&buf[4])), n/2)))
	return (strings.Contains(name, `\msys-`) || strings.Contains(name, `\cygwin-`)) && strings.Contains(name, "-pty")
}

// readHidden читает строку с консоли (CONIN$) с выключенным echo. Echo
// восстанавливается и по Ctrl-C.
func readHidden(prompt string) (string, error) {
	conin, err := os.OpenFile("CONIN$", os.O_RDWR, 0)
	if err != nil {
		return "", errors.New("нет консоли для скрытого ввода (Git Bash/mintty: запусти через winpty sec …) — либо подай значение через stdin или --clipboard")
	}
	defer conin.Close()
	out := os.Stderr
	if conout, cerr := os.OpenFile("CONOUT$", os.O_WRONLY, 0); cerr == nil {
		defer conout.Close()
		out = conout
	}
	fmt.Fprint(out, prompt)

	h := windows.Handle(conin.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return "", fmt.Errorf("GetConsoleMode: %w", err)
	}
	if err := windows.SetConsoleMode(h, mode&^windows.ENABLE_ECHO_INPUT); err != nil {
		return "", fmt.Errorf("SetConsoleMode: %w", err)
	}
	restore := func() { _ = windows.SetConsoleMode(h, mode) }
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	done := make(chan struct{})
	go func() {
		select {
		case <-sig:
			restore()
			fmt.Fprintln(out)
			os.Exit(130)
		case <-done:
		}
	}()
	line, rerr := readLine(conin)
	close(done)
	signal.Stop(sig)
	restore()
	fmt.Fprintln(out)
	if rerr != nil && line == "" {
		return "", rerr
	}
	return line, nil
}

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procOpenClipboard    = user32.NewProc("OpenClipboard")
	procCloseClipboard   = user32.NewProc("CloseClipboard")
	procEmptyClipboard   = user32.NewProc("EmptyClipboard")
	procGetClipboardData = user32.NewProc("GetClipboardData")
	procSetClipboardData = user32.NewProc("SetClipboardData")
	procRegisterFormatW  = user32.NewProc("RegisterClipboardFormatW")
	procGlobalAlloc      = kernel32.NewProc("GlobalAlloc")
	procGlobalLock       = kernel32.NewProc("GlobalLock")
	procGlobalUnlock     = kernel32.NewProc("GlobalUnlock")
	procGlobalFree       = kernel32.NewProc("GlobalFree")
)

const (
	cfUnicodeText = 13     // CF_UNICODETEXT
	gmemMoveable  = 0x0002 // GMEM_MOVEABLE — SetClipboardData требует movable-блок
)

// hglobalPtr превращает результат GlobalLock (uintptr) в unsafe.Pointer.
// Память принадлежит куче Windows (HGLOBAL) — GC Go её не двигает и не
// освобождает, указатель валиден до GlobalUnlock/GlobalFree. Прямая конверсия
// uintptr→Pointer ложно срабатывает в go vet (unsafeptr), поэтому через &p.
func hglobalPtr(p uintptr) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&p))
}

// openClipboard с ретраями: буфер может быть на мгновение занят другим
// приложением (менеджером буфера и т.п.).
func openClipboard() error {
	for i := 0; i < 10; i++ {
		if r, _, _ := procOpenClipboard.Call(0); r != 0 {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return errors.New("буфер обмена занят другим приложением")
}

func clipboardRead() (string, error) {
	if err := openClipboard(); err != nil {
		return "", err
	}
	defer procCloseClipboard.Call()
	h, _, _ := procGetClipboardData.Call(cfUnicodeText)
	if h == 0 {
		return "", nil // пусто или не текст — как пустой pbpaste
	}
	p, _, _ := procGlobalLock.Call(h)
	if p == 0 {
		return "", errors.New("GlobalLock")
	}
	defer procGlobalUnlock.Call(h)
	return windows.UTF16PtrToString((*uint16)(hglobalPtr(p))), nil
}

// clipboardWrite кладёт значение в буфер обмена и помечает его форматами,
// исключающими попадание в историю Win+V и облачную синхронизацию.
// Пустая строка — просто очистка буфера.
func clipboardWrite(s string) error {
	if err := openClipboard(); err != nil {
		return err
	}
	defer procCloseClipboard.Call()
	procEmptyClipboard.Call()
	if s == "" {
		return nil
	}
	u16, err := windows.UTF16FromString(s) // с завершающим NUL
	if err != nil {
		return err
	}
	// метки исключения — строго ДО секрета: если хоть одна не встала, секрет в
	// буфер не кладём вовсе (иначе он утёк бы в историю Win+V и облачную
	// синхронизацию, а команда отчиталась бы об успехе). Буфер уже очищен.
	for _, name := range []string{
		"ExcludeClipboardContentFromMonitorProcessing",
		"CanIncludeInClipboardHistory",
		"CanUploadToCloudClipboard",
	} {
		id := registerFormat(name)
		if id == 0 {
			return fmt.Errorf("формат %s не зарегистрирован — без защиты от истории Win+V секрет в буфер не кладу", name)
		}
		var zero [4]byte // DWORD 0 — «нельзя»
		if err := setClipboardBytes(id, zero[:]); err != nil {
			return fmt.Errorf("метка %s: %w — без защиты от истории Win+V секрет в буфер не кладу", name, err)
		}
	}
	return setClipboardBytes(cfUnicodeText,
		unsafe.Slice((*byte)(unsafe.Pointer(&u16[0])), len(u16)*2))
}

func registerFormat(name string) uintptr {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0
	}
	id, _, _ := procRegisterFormatW.Call(uintptr(unsafe.Pointer(p)))
	return id
}

// setClipboardBytes копирует data в movable-глобальный блок и отдаёт его
// буферу обмена. После успешного SetClipboardData блоком владеет система.
func setClipboardBytes(format uintptr, data []byte) error {
	h, _, _ := procGlobalAlloc.Call(gmemMoveable, uintptr(len(data)))
	if h == 0 {
		return errors.New("GlobalAlloc")
	}
	p, _, _ := procGlobalLock.Call(h)
	if p == 0 {
		procGlobalFree.Call(h)
		return errors.New("GlobalLock")
	}
	copy(unsafe.Slice((*byte)(hglobalPtr(p)), len(data)), data)
	procGlobalUnlock.Call(h)
	if r, _, _ := procSetClipboardData.Call(format, h); r == 0 {
		procGlobalFree.Call(h)
		return errors.New("SetClipboardData")
	}
	return nil
}
