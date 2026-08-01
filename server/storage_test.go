package main

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testStorage(t *testing.T) *Storage {
	t.Helper()
	st, err := NewStorage(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func testRecord(id string, once bool, ttl time.Duration) SecretRecord {
	now := time.Now().UTC()
	return SecretRecord{
		V: 1, ID: id, Blob: []byte("secshare\x01fake-nonce12fake-ciphertext"),
		Once: once, TokenName: "kai", CreatedAt: now, ExpiresAt: now.Add(ttl),
	}
}

func TestClaimOnce(t *testing.T) {
	st := testStorage(t)
	if err := st.Save(testRecord("abc123", true, time.Hour)); err != nil {
		t.Fatal(err)
	}
	rec, ok := st.Claim("abc123")
	if !ok || string(rec.Blob) == "" || rec.Claims != 1 {
		t.Fatalf("первый клейм: ok=%v claims=%d", ok, rec.Claims)
	}
	if _, ok := st.Claim("abc123"); ok {
		t.Fatal("повторный клейм одноразового прошёл")
	}
}

func TestClaimMulti(t *testing.T) {
	st := testStorage(t)
	if err := st.Save(testRecord("abc123", false, time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.Claim("abc123"); !ok {
		t.Fatal("первый клейм не прошёл")
	}
	rec, ok := st.Claim("abc123")
	if !ok || rec.Claims != 2 {
		t.Fatalf("второй клейм multi: ok=%v claims=%d, want true/2", ok, rec.Claims)
	}
}

// Гонка double-claim: 32 горутины бьются за одноразовый секрет — победить
// обязана ровно одна.
func TestClaimOnceRace(t *testing.T) {
	st := testStorage(t)
	if err := st.Save(testRecord("race1", true, time.Hour)); err != nil {
		t.Fatal(err)
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, ok := st.Claim("race1"); ok {
				wins.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("побед %d, want 1", wins.Load())
	}
}

func TestClaimExpired(t *testing.T) {
	st := testStorage(t)
	if err := st.Save(testRecord("old1", false, time.Hour)); err != nil {
		t.Fatal(err)
	}
	st.now = func() time.Time { return time.Now().UTC().Add(2 * time.Hour) }
	if _, ok := st.Claim("old1"); ok {
		t.Fatal("протухший секрет выдан")
	}
	if _, err := os.Stat(st.path("old1")); !os.IsNotExist(err) {
		t.Fatal("протухший файл не удалён при клейме")
	}
}

func TestListOwnerAndDelete(t *testing.T) {
	st := testStorage(t)
	mine := testRecord("mine1", true, time.Hour)
	other := testRecord("other1", true, time.Hour)
	other.TokenName = "someone"
	if err := st.Save(mine); err != nil {
		t.Fatal(err)
	}
	if err := st.Save(other); err != nil {
		t.Fatal(err)
	}

	recs, err := st.List("kai")
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].ID != "mine1" {
		t.Fatalf("List(kai) = %+v, want только mine1", recs)
	}
	if recs[0].Blob != nil {
		t.Fatal("List отдаёт блобы")
	}

	if st.Delete("mine1", "someone") {
		t.Fatal("чужая запись удалена")
	}
	if !st.Delete("mine1", "kai") {
		t.Fatal("своя запись не удалена")
	}
	if st.Delete("mine1", "kai") {
		t.Fatal("повторный Delete прошёл")
	}
}

func TestReap(t *testing.T) {
	st := testStorage(t)
	if err := st.Save(testRecord("fresh", false, time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := st.Save(testRecord("stale", false, time.Minute)); err != nil {
		t.Fatal(err)
	}
	// зависший файл клейма и осиротевший tmp «из прошлого»
	old := filepath.Join(st.dir, "claimed", "leftover")
	if err := os.WriteFile(old, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}

	st.now = func() time.Time { return time.Now().UTC().Add(30 * time.Minute) }
	st.Reap()

	if _, err := os.Stat(st.path("fresh")); err != nil {
		t.Fatal("живой секрет удалён reaper-ом")
	}
	if _, err := os.Stat(st.path("stale")); !os.IsNotExist(err) {
		t.Fatal("протухший секрет пережил reaper")
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("зависший файл клейма пережил reaper")
	}
}
