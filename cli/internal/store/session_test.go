package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsOwnFileOnlyGeneratedArtifacts(t *testing.T) {
	for _, base := range []string{"store.enc", "custom[store].db"} {
		t.Run(base, func(t *testing.T) {
			dir := t.TempDir()
			t.Chdir(dir)
			if err := os.Mkdir("store", 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir("neighbor", 0o700); err != nil {
				t.Fatal(err)
			}
			sp := filepath.Join(dir, "store", base)
			t.Setenv("SEC_STORE", sp)
			own := []string{base, base + "-wal", base + "-shm", base + "-journal", base + ".lock", base + ".rekey-key", base + ".tmp"}
			for _, pattern := range []string{base + ".*.tmp", base + ".new-*.tmp", base + ".v2-*.tmp", base + ".rekey-key.*.tmp"} {
				f, err := os.CreateTemp(filepath.Dir(sp), pattern)
				if err != nil {
					t.Fatal(err)
				}
				f.Close()
				name := filepath.Base(f.Name())
				own = append(own, name)
				if pattern == base+".new-*.tmp" {
					for _, suffix := range []string{"-wal", "-shm", "-journal"} {
						own = append(own, name+suffix)
					}
				}
			}
			bak, err := writeBackup(sp, []byte("synthetic-encrypted-fixture"))
			if err != nil {
				t.Fatal(err)
			}
			own = append(own, filepath.Base(bak))
			user := []string{
				base + ".env", base + ".txt", base + "-export.env", base + ".leftover.tmp",
				base + ".new-export.tmp", base + ".v2-not-a-date.bak", base + ".v2-20261024T120000.123456789Z.bak.env",
				base + ".123.tmp-wal", base + ".v2-123.tmp-shm", base + ".rekey-key.env",
				base + "-wal.env", base + ".new-123.tmp.txt", base + ".tmp.env", "other.enc-wal",
				base + ".new-123.tmp-wal-shm", base + ".v2-20261324T120000.123456789Z.bak",
			}
			for _, storePath := range []string{sp, filepath.Join("store", base)} {
				t.Setenv("SEC_STORE", storePath)
				for _, name := range own {
					for _, p := range []string{filepath.Join(dir, "store", name), filepath.Join("store", name), "store/../store/" + name} {
						if !IsOwnFile(p) {
							t.Errorf("generated artifact not excluded: %s", p)
						}
					}
					if IsOwnFile(filepath.Join("neighbor", name)) {
						t.Errorf("neighbor file excluded: %s", name)
					}
				}
				for _, name := range user {
					if IsOwnFile(filepath.Join("store", name)) {
						t.Errorf("user file excluded: %s", name)
					}
				}
			}
			if err := os.Symlink(filepath.Join(dir, "store"), filepath.Join(dir, "alias")); err == nil {
				if !IsOwnFile(filepath.Join("alias", base+"-wal")) || IsOwnFile(filepath.Join("alias", base+".env")) {
					t.Error("directory alias misclassified")
				}
			}
		})
	}
}
