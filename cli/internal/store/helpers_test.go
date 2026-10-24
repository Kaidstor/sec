package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// testEnv — стор и все побочные файлы во временном каталоге, мастер-ключ из
// SEC_KEY (системное хранилище ключа не трогается).
func testEnv(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SEC_STORE", filepath.Join(dir, "store.enc"))
	t.Setenv("SEC_KEY", hex.EncodeToString(key))
	t.Setenv("SEC_KEY_FILE", filepath.Join(dir, "key"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	t.Setenv("SEC_NO_USAGE", "1")
	t.Cleanup(CloseAll)
	return key
}

func writeLegacy(t *testing.T, key []byte, ps *portableStore) {
	t.Helper()
	pt, err := json.Marshal(ps)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := legacyEncrypt(key, pt)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(Path()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(Path(), ct, 0o600); err != nil {
		t.Fatal(err)
	}
}

func txt(v Value) string {
	s, err := v.Load()
	if err != nil {
		panic(err)
	}
	return s
}

func sp(s string) *string { return &s }
