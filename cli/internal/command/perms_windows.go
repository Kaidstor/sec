//go:build windows

package command

// Windows-проверка прав файла хранилища для sec doctor: chmod там не работает,
// защита — NTFS ACL. Читаем DACL и ищем ACE, дающие чтение широким группам
// (Everyone / Authenticated Users / BUILTIN\Users) — например когда SEC_STORE
// указывает в общую папку с унаследованными разрешениями.

import (
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// storePermsStatus возвращает строку для отчёта doctor и ok=false, если DACL
// даёт чтение широким группам либо его не удалось проверить.
func storePermsStatus(path string, _ os.FileInfo) (string, bool) {
	broad, err := broadReadAccess(path)
	if err != nil {
		return fmt.Sprintf("права хранилища: не удалось проверить NTFS ACL (%v) — проверь вручную: icacls %s", err, path), false
	}
	if len(broad) > 0 {
		return fmt.Sprintf("хранилище доступно на чтение широким группам: %s — убери лишние разрешения: icacls %s /inheritance:r /grant:r %%USERNAME%%:F", strings.Join(broad, ", "), path), false
	}
	return "права хранилища: NTFS ACL без широких групп (Everyone/Users)", true
}

// broadReadAccess возвращает имена широких SID, которым DACL файла даёт чтение.
func broadReadAccess(path string) ([]string, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return nil, err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return nil, err
	}
	if dacl == nil {
		return []string{"все (NULL DACL)"}, nil // отсутствие DACL — полный доступ каждому
	}
	broadSids := []struct {
		kind windows.WELL_KNOWN_SID_TYPE
		name string
	}{
		{windows.WinWorldSid, "Everyone"},
		{windows.WinAuthenticatedUserSid, "Authenticated Users"},
		{windows.WinBuiltinUsersSid, `BUILTIN\Users`},
	}
	const readMask = windows.GENERIC_READ | windows.FILE_READ_DATA
	var hits []string
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Mask&readMask == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		for _, b := range broadSids {
			if sid.IsWellKnown(b.kind) {
				hits = append(hits, b.name)
			}
		}
	}
	return dedupe(hits), nil
}
