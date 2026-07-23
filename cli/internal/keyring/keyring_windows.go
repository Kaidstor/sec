//go:build windows

package keyring

// Системное хранилище ключа на Windows — Credential Manager (generic
// credential) через advapi32: CredReadW/CredWriteW. Значение уходит в blob
// структуры CREDENTIALW — в argv/командную строку не попадает. Persist —
// LOCAL_MACHINE (не ENTERPRISE): секрет не роумится с доменным профилем.

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	advapi32       = windows.NewLazySystemDLL("advapi32.dll")
	procCredReadW  = advapi32.NewProc("CredReadW")
	procCredWriteW = advapi32.NewProc("CredWriteW")
	procCredFree   = advapi32.NewProc("CredFree")
)

const (
	credTypeGeneric         = 1 // CRED_TYPE_GENERIC
	credPersistLocalMachine = 2 // CRED_PERSIST_LOCAL_MACHINE
)

// credentialW — CREDENTIALW из wincred.h (раскладка полей важна).
type credentialW struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        windows.Filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

// credTarget — TargetName записи в Credential Manager (аналог service у Keychain).
func credTarget() string { return keyringService() + "/master" }

func osKeyringAvailable() bool {
	return procCredReadW.Find() == nil && procCredWriteW.Find() == nil
}

func osKeyringName() string {
	return fmt.Sprintf("Windows Credential Manager (target=%s)", credTarget())
}

func osKeyringRead() (string, error) {
	target, err := windows.UTF16PtrFromString(credTarget())
	if err != nil {
		return "", err
	}
	var pcred *credentialW
	r, _, callErr := procCredReadW.Call(
		uintptr(unsafe.Pointer(target)), credTypeGeneric, 0,
		uintptr(unsafe.Pointer(&pcred)))
	if r == 0 {
		return "", callErr // обычно ERROR_NOT_FOUND — ключа ещё нет
	}
	defer procCredFree.Call(uintptr(unsafe.Pointer(pcred)))
	if pcred.CredentialBlobSize == 0 || pcred.CredentialBlob == nil {
		return "", errors.New("пустая запись в Credential Manager")
	}
	blob := unsafe.Slice(pcred.CredentialBlob, pcred.CredentialBlobSize)
	return string(blob), nil
}

func osKeyringWrite(hexKey string) error {
	target, err := windows.UTF16PtrFromString(credTarget())
	if err != nil {
		return err
	}
	user, err := windows.UTF16PtrFromString("master")
	if err != nil {
		return err
	}
	blob := []byte(hexKey)
	cred := credentialW{
		Type:               credTypeGeneric,
		TargetName:         target,
		CredentialBlob:     &blob[0],
		CredentialBlobSize: uint32(len(blob)),
		Persist:            credPersistLocalMachine,
		UserName:           user,
	}
	r, _, callErr := procCredWriteW.Call(uintptr(unsafe.Pointer(&cred)), 0)
	if r == 0 {
		return callErr
	}
	return nil
}
