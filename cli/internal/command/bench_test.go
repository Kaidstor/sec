//go:build !windows

package command

// Синтетический бенчмарк форматов стора на настоящих процессах. Только по
// запросу (тяжёлый: ~450 МиБ шифротекста на каждый формат, всё во временном
// каталоге, удаляется по завершении):
//
//	SEC_BENCH=1 SEC_BENCH_BIN=/tmp/sec-new SEC_BENCH_BASE_BIN=/tmp/sec-base \
//	  go test ./internal/command -run TestBenchSyntheticStore -v -timeout 60m
//
// SEC_BENCH_BIN — бинарь этой ветки, SEC_BENCH_BASE_BIN (необязательно) —
// бинарь до SQLite, он гоняется на SECSTOR2. Форма стора повторяет реальную:
// 652 ключа, из них 333 бинарных файла (~1.34 МБ base64 каждый, ~447 МиБ
// всего), у мелких ключей история. Значения синтетические.

import (
	"encoding/base64"
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/kaidstor/sec/internal/store"
)

func TestBenchSyntheticStore(t *testing.T) {
	if os.Getenv("SEC_BENCH") == "" {
		t.Skip("SEC_BENCH=1 — тяжёлый синтетический бенчмарк")
	}
	bin := os.Getenv("SEC_BENCH_BIN")
	if bin == "" {
		t.Fatal("нужен SEC_BENCH_BIN")
	}
	base := os.Getenv("SEC_BENCH_BASE_BIN")
	runs := 15
	if n, err := strconv.Atoi(os.Getenv("SEC_BENCH_RUNS")); err == nil && n > 0 {
		runs = n
	}
	only := os.Getenv("SEC_BENCH_ONLY") // подстрока имени кейса — прогнать часть

	root := t.TempDir()
	v3 := filepath.Join(root, "v3", "store.enc")
	v2 := filepath.Join(root, "v2", "store.enc")
	start := time.Now()
	genSynthetic(t, v3)
	genSynthetic(t, v2)
	t.Setenv("SEC_STORE", v2)
	if _, err := store.MigrateToV2(); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{v2, v3} {
		fi, _ := os.Stat(p)
		t.Logf("%s: %d байт", filepath.Base(filepath.Dir(p)), fi.Size())
	}
	t.Logf("генерация: %s", time.Since(start).Round(time.Second))

	out := filepath.Join(root, "out.bin")
	cases := []struct {
		name  string
		stdin func(i int) string
		args  []string
	}{
		{"get 32 симв.", nil, []string{"get", "app00/KEY_0000"}},
		{"ls app --json", nil, []string{"ls", "app00", "--json"}},
		{"ls --json (всё)", nil, []string{"ls", "--json"}},
		{"find", nil, []string{"find", "KEY_01"}},
		{"run --only", nil, []string{"run", "app00", "--only", "KEY_0000", "--", "true"}},
		{"get файл 1.3 МБ --out", nil, []string{"get", "files/FILE_000", "--out", out}},
		{"set мелкий", func(i int) string { return fmt.Sprintf("new-value-%04d-%s", i, strings.Repeat("x", 16)) }, []string{"set", "app00/KEY_0001"}},
	}
	type target struct{ label, bin, store string }
	targets := []target{{"new/v3", bin, v3}, {"new/v2", bin, v2}}
	if base != "" {
		targets = append(targets, target{"base/v2", base, v2})
	}
	var report strings.Builder
	fmt.Fprintf(&report, "%-24s %-8s %9s %9s %9s %10s\n", "команда", "стор", "p50 мс", "p95 мс", "max мс", "maxRSS МБ")
	for _, c := range cases {
		if only != "" && !strings.Contains(c.name, only) {
			continue
		}
		for _, tg := range targets {
			var durs []time.Duration
			var rss int64
			for i := 0; i <= runs; i++ { // первый прогон — прогрев кэша ФС, не считаем
				cmd := exec.Command(tg.bin, c.args...)
				cmd.Env = benchEnv(tg.store)
				if c.stdin != nil {
					cmd.Stdin = strings.NewReader(c.stdin(i))
				}
				t0 := time.Now()
				b, err := cmd.CombinedOutput()
				d := time.Since(t0)
				if err != nil {
					t.Fatalf("%s %s: %v\n%s", tg.label, c.name, err, b)
				}
				if i == 0 {
					continue
				}
				durs = append(durs, d)
				if ru, ok := cmd.ProcessState.SysUsage().(*syscall.Rusage); ok && ru.Maxrss > rss {
					rss = ru.Maxrss
				}
			}
			sort.Slice(durs, func(i, j int) bool { return durs[i] < durs[j] })
			p := func(q float64) float64 { return float64(durs[int(q*float64(len(durs)-1))].Microseconds()) / 1000 }
			fmt.Fprintf(&report, "%-24s %-8s %9.1f %9.1f %9.1f %10.1f\n", c.name, tg.label, p(0.5), p(0.95), p(1), float64(rssBytes(rss))/(1<<20))
		}
	}
	t.Log("\n" + report.String())
	if p := os.Getenv("SEC_BENCH_OUT"); p != "" {
		os.WriteFile(p, []byte(report.String()), 0o600)
	}
}

func benchEnv(storePath string) []string {
	env := []string{"SEC_STORE=" + storePath, "SEC_KEY=" + os.Getenv("SEC_KEY"), "SEC_NO_USAGE=1", "SEC_NO_SKILL_SYNC=1",
		"SEC_KEY_FILE=" + filepath.Join(filepath.Dir(storePath), "key"), "HOME=" + filepath.Dir(storePath), "PATH=" + os.Getenv("PATH")}
	return env
}

// genSynthetic пишет стор SQLite формы реального: 319 мелких ключей в 20
// проектах (с историей) и 333 бинарных файла ~1 МБ (≈1.34 МБ base64).
func genSynthetic(t *testing.T, p string) {
	t.Helper()
	t.Setenv("SEC_STORE", p)
	t.Setenv("SEC_KEY", strings.Repeat("ab", 32))
	t.Setenv("SEC_NO_USAGE", "1")
	st, _, _, err := store.Begin(true)
	if err != nil {
		t.Fatal(err)
	}
	rnd := rand.New(rand.NewChaCha8([32]byte{1}))
	for i := 0; i < 319; i++ {
		proj := fmt.Sprintf("app%02d", i%20)
		k := fmt.Sprintf("KEY_%04d", i)
		for v := 0; v < 1+i%3; v++ {
			store.Put(st.Project(proj), k, fmt.Sprintf("%032x", rnd.Uint64())[:32])
		}
	}
	raw := make([]byte, 1_004_000)
	for i := 0; i < 333; i++ {
		for j := range raw {
			raw[j] = byte(rnd.Uint32())
		}
		store.PutEnc(st.Project("files"), fmt.Sprintf("FILE_%03d", i), base64.StdEncoding.EncodeToString(raw), store.EncB64)
	}
	if err := st.Commit(); err != nil {
		t.Fatal(err)
	}
}

// rssBytes — ru_maxrss в байтах: macOS отдаёт байты, Linux — килобайты.
func rssBytes(v int64) int64 {
	if runtime.GOOS == "linux" {
		return v * 1024
	}
	return v
}
