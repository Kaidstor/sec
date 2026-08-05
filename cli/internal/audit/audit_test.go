package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func tempStore(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("SEC_STORE", filepath.Join(dir, "store.enc"))
	return dir
}

// Ротация уводит журнал в архив с датой, а не затирает предыдущее поколение:
// прежняя схема (audit.jsonl.1) теряла всё старше позапрошлой ротации.
func TestRotateKeepsGenerations(t *testing.T) {
	dir := tempStore(t)
	base := time.Date(2026, 1, 10, 12, 0, 0, 0, time.Local)

	for i, day := range []time.Time{base, base.AddDate(0, 6, 0), base.AddDate(1, 0, 0)} {
		if err := os.WriteFile(Path(), []byte(`{"ts":"x","op":"gen`+string(rune('0'+i))+`"}`+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		rotate(Path(), day)
	}
	archives := Archives()
	if len(archives) != 3 {
		t.Fatalf("ожидалось 3 архива, есть %d: %v", len(archives), archives)
	}
	if !strings.Contains(archives[0], "20260110") || !strings.Contains(archives[2], "20270110") {
		t.Errorf("архивы должны идти от старых к свежим: %v", archives)
	}
	_ = dir
}

// Архивы старше KeepDays подчищаются, но год данных остаётся всегда.
func TestRotatePrunesOlderThanKeepDays(t *testing.T) {
	tempStore(t)
	now := time.Date(2027, 3, 1, 12, 0, 0, 0, time.Local)
	old := now.AddDate(0, 0, -KeepDays-10)
	fresh := now.AddDate(0, 0, -300) // почти год назад — обязан пережить ротацию

	for _, ts := range []time.Time{old, fresh} {
		name := filepath.Join(filepath.Dir(Path()), archivePrefix+ts.Format(archiveTimeFormat)+archiveSuffix)
		if err := os.WriteFile(name, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(Path(), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rotate(Path(), now)

	got := strings.Join(Archives(), " ")
	if strings.Contains(got, old.Format(archiveTimeFormat)) {
		t.Errorf("архив старше KeepDays должен удаляться: %s", got)
	}
	if !strings.Contains(got, fresh.Format(archiveTimeFormat)) {
		t.Errorf("данные за последний год терять нельзя: %s", got)
	}
}

// Read читает только текущий файл (быстрый путь sec log -n), ReadAll — всё.
func TestReadVsReadAll(t *testing.T) {
	tempStore(t)
	if err := os.WriteFile(Path(), []byte(`{"ts":"2026-01-01T00:00:00Z","op":"старое"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rotate(Path(), time.Date(2026, 2, 1, 0, 0, 0, 0, time.Local))
	Record("новое", "proj/KEY", "")

	if got := Read(); len(got) != 1 || got[0].Op != "новое" {
		t.Errorf("Read должен видеть только текущий файл: %+v", got)
	}
	all := ReadAll()
	if len(all) != 2 || all[0].Op != "старое" || all[1].Op != "новое" {
		t.Errorf("ReadAll должен склеивать архивы и текущий по времени: %+v", all)
	}
}

// Легаси-файл прежней схемы читается, но по возрасту не удаляется.
func TestLegacyArchiveIsRead(t *testing.T) {
	tempStore(t)
	if err := os.WriteFile(Path()+".1", []byte(`{"ts":"2025-01-01T00:00:00Z","op":"легаси"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	Record("свежее", "proj/KEY", "")
	all := ReadAll()
	if len(all) != 2 || all[0].Op != "легаси" {
		t.Errorf("audit.jsonl.1 должен попадать в ReadAll: %+v", all)
	}
}
