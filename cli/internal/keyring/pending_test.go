package keyring

import (
	"os"
	"path/filepath"
	"testing"
)

// Слот rekey для бэкенда file: ключ ложится рядом с основным, Promote делает
// его основным, ClearPending убирает слот. Системное хранилище не трогается.
func TestPendingFileBackend(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SEC_KEY_FILE", filepath.Join(dir, "key"))
	oldHex, _, _ := NewHex()
	if err := writeKeyFile(FilePath(), oldHex); err != nil {
		t.Fatal(err)
	}
	if k, err := LoadPending("file", ""); k != nil || err != nil {
		t.Fatalf("пустой слот: %v %v", k, err)
	}
	newHex, newKey, _ := NewHex()
	if err := SavePending("file", newHex, ""); err != nil {
		t.Fatal(err)
	}
	if k, err := LoadPending("file", ""); err != nil || string(k) != string(newKey) {
		t.Fatalf("слот не читается: %v", err)
	}
	if fi, _ := os.Stat(FilePath() + ".next"); fi.Mode().Perm() != 0o600 {
		t.Errorf("права слота %o", fi.Mode().Perm())
	}
	if data, _ := os.ReadFile(FilePath()); string(data) != oldHex+"\n" {
		t.Fatal("основной ключ не должен меняться до Promote")
	}
	if err := Promote("file", newHex); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(FilePath()); string(data) != newHex+"\n" {
		t.Fatal("Promote не записал основной ключ")
	}
	if err := ClearPending("file", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(FilePath() + ".next"); !os.IsNotExist(err) {
		t.Fatal("слот не очищен")
	}
	if err := ClearPending("file", ""); err != nil {
		t.Fatal("повторная очистка пустого слота — не ошибка")
	}
}
