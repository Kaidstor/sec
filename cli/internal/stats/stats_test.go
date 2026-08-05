package stats

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func tempStore(t *testing.T) {
	t.Helper()
	t.Setenv("SEC_STORE", filepath.Join(t.TempDir(), "store.enc"))
	t.Setenv("SEC_NO_USAGE", "")
}

func TestRecordAccumulates(t *testing.T) {
	tempStore(t)
	day1 := time.Date(2026, 8, 4, 10, 0, 0, 0, time.UTC)
	day2 := day1.Add(24 * time.Hour)

	Record("run", []string{"--only"}, day1)
	Record("run", nil, day2)
	Record("get", []string{"--peek"}, day2)

	f := Load()
	if f.Keys["run"].N != 2 || f.Keys["run"].First != "2026-08-04" || f.Keys["run"].Last != "2026-08-05" {
		t.Errorf("итог по run: %+v", f.Keys["run"])
	}
	if f.Keys["run --only"].N != 1 {
		t.Errorf("флаг должен считаться отдельным ключом: %+v", f.Keys["run --only"])
	}
	// разбивка по дням — только команды: флаги ещё и по дням раздули бы файл
	if f.Days["2026-08-05"]["run"] != 1 || f.Days["2026-08-05"]["get"] != 1 {
		t.Errorf("разбивка по дням: %+v", f.Days)
	}
	if _, ok := f.Days["2026-08-05"]["run --only"]; ok {
		t.Error("флаги в дневную разбивку не пишутся")
	}
	if got := f.SortedDays(); len(got) != 2 || got[0] != "2026-08-05" {
		t.Errorf("дни должны идти от свежих к старым: %v", got)
	}
}

// Итоги за всё время не обрезаются, иначе «ни разу не использовалось» соврёт.
func TestPruneKeepsTotals(t *testing.T) {
	tempStore(t)
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < maxDays+5; i++ {
		Record("run", nil, base.AddDate(0, 0, i))
	}
	f := Load()
	if len(f.Days) != maxDays {
		t.Errorf("дней осталось %d, ожидалось %d", len(f.Days), maxDays)
	}
	if f.Keys["run"].N != maxDays+5 {
		t.Errorf("итог обрезался вместе с днями: %+v", f.Keys["run"])
	}
	if f.Keys["run"].First != "2024-01-01" {
		t.Errorf("дата первого запуска потеряна: %+v", f.Keys["run"])
	}
}

func TestSecNoUsageDisablesAndBadFileIsHarmless(t *testing.T) {
	tempStore(t)
	t.Setenv("SEC_NO_USAGE", "1")
	Record("run", nil, time.Now())
	if len(Load().Keys) != 0 {
		t.Error("SEC_NO_USAGE должен выключать счётчик")
	}
	t.Setenv("SEC_NO_USAGE", "")

	if err := os.WriteFile(Path(), []byte("{битый жсон"), 0o600); err != nil {
		t.Fatal(err)
	}
	if len(Load().Keys) != 0 {
		t.Error("битый файл должен читаться как пустая статистика")
	}
	Record("run", nil, time.Now()) // и переписываться без паники
	if Load().Keys["run"].N != 1 {
		t.Error("после битого файла счётчик должен начаться заново")
	}
}
