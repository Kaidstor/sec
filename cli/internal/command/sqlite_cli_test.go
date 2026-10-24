package command

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/kaidstor/sec/internal/store"
)

// TestHelperSec — процесс-помощник: настоящий отдельный процесс sec поверх
// временного стора (env наследуется от теста). Аргументы — в SEC_TEST_ARGS.
func TestHelperSec(t *testing.T) {
	raw := os.Getenv("SEC_TEST_ARGS")
	if raw == "" {
		t.Skip("только как процесс-помощник")
	}
	var args []string
	if err := json.Unmarshal([]byte(raw), &args); err != nil {
		os.Exit(99)
	}
	os.Exit(Run(args))
}

type secResult struct {
	code           int
	stdout, stderr string
}

func secCmd(stdin string, args ...string) *exec.Cmd {
	raw, _ := json.Marshal(args)
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperSec$")
	cmd.Env = append(os.Environ(), "SEC_TEST_ARGS="+string(raw))
	cmd.Stdin = strings.NewReader(stdin)
	return cmd
}

func secProc(t *testing.T, stdin string, args ...string) secResult {
	t.Helper()
	cmd := secCmd(stdin, args...)
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return secResult{code, o.String(), e.String()}
}

func cliEnv(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("SEC_STORE", filepath.Join(dir, "store.enc"))
	t.Setenv("SEC_KEY", strings.Repeat("cd", 32))
	t.Setenv("SEC_KEY_FILE", filepath.Join(dir, "key"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	t.Setenv("SEC_NO_USAGE", "1")
	t.Setenv("SEC_NO_SKILL_SYNC", "1")
	t.Cleanup(store.CloseAll)
	return dir
}

// get --once и параллельный set: показанное значение и удаление — из одной
// транзакции. Раньше once читал до блокировки: показывал старое значение и
// удалял уже записанное новое — новое терялось без следа.
func TestOnceVersusConcurrentSet(t *testing.T) {
	cliEnv(t)
	for i := 0; i < 12; i++ {
		if r := secProc(t, "v0", "set", "app/K"); r.code != 0 {
			t.Fatalf("set: %+v", r)
		}
		var once, set secResult
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); once = secProc(t, "", "get", "app/K", "--once") }()
		go func() { defer wg.Done(); set = secProc(t, "v1", "set", "app/K") }()
		wg.Wait()
		if set.code != 0 {
			t.Fatalf("set: %+v", set)
		}
		get := secProc(t, "", "get", "app/K")
		switch strings.TrimSpace(once.stdout) {
		case "v0": // once раньше set — новое значение обязано остаться
			if strings.TrimSpace(get.stdout) != "v1" {
				t.Fatalf("итерация %d: once показал v0, а записанное v1 пропало (%+v)", i, get)
			}
		case "v1": // set раньше once — показано и удалено новое
			if get.code != 3 {
				t.Fatalf("итерация %d: once показал v1, но ключ остался: %+v", i, get)
			}
		default:
			if once.code != 3 { // set удалил бы? нет — once мог не найти ключ только в гонке с rm
				t.Fatalf("итерация %d: once: %+v", i, once)
			}
		}
		secProc(t, "", "rm", "app/K")
	}
}

// Параллельные HOTP-коды: каждый процесс получает свой счётчик.
func TestHOTPConcurrentCountersDistinct(t *testing.T) {
	cliEnv(t)
	uri := "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=0"
	if r := secProc(t, uri, "set", "app/OTP"); r.code != 0 {
		t.Fatalf("set: %+v", r)
	}
	const n = 6
	res := make([]secResult, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) { defer wg.Done(); res[i] = secProc(t, "", "otp", "app/OTP", "--json") }(i)
	}
	wg.Wait()
	var counters []int
	for _, r := range res {
		var env struct {
			Data struct {
				Counter int `json:"counter"`
			} `json:"data"`
		}
		if r.code != 0 || json.Unmarshal([]byte(r.stdout), &env) != nil {
			t.Fatalf("otp: %+v", r)
		}
		if strings.Contains(r.stdout+r.stderr, "не сохранён") {
			t.Fatalf("счётчик не сохранён: %+v", r)
		}
		counters = append(counters, env.Data.Counter)
	}
	sort.Ints(counters)
	for i, c := range counters {
		if c != i {
			t.Fatalf("счётчики должны быть 0..%d без повторов: %v", n-1, counters)
		}
	}
}

// ls --json сохраняет поля, которые читают GUI и Raycast, и не раскрывает
// значения; get/raw stdout — голое значение.
func TestLsJSONFieldsOnSQLite(t *testing.T) {
	dir := cliEnv(t)
	secProc(t, "value-one-123", "set", "app/TOKEN")
	secProc(t, "value-two-456", "set", "app/TOKEN")
	bin := filepath.Join(dir, "cert.bin")
	os.WriteFile(bin, []byte{0, 1, 2, 3, 0xff}, 0o600)
	secProc(t, "", "set", "app/CERT", "--from-file", bin)
	secProc(t, "", "link", "web/TOKEN", "app/TOKEN")

	r := secProc(t, "", "ls", "app", "--json")
	var env struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &env); err != nil {
		t.Fatalf("%v: %s", err, r.stdout)
	}
	byKey := map[string]map[string]any{}
	for _, k := range env.Data {
		byKey[k["key"].(string)] = k
	}
	tok, cert := byKey["TOKEN"], byKey["CERT"]
	if tok["chars"] != float64(13) || tok["history"] != float64(1) || !strings.HasPrefix(tok["fingerprint"].(string), "fp:") {
		t.Errorf("TOKEN: %v", tok)
	}
	if cert["enc"] != "b64" || cert["chars"] != float64(5) {
		t.Errorf("CERT: %v", cert)
	}
	if strings.Contains(r.stdout, "value-two") {
		t.Fatal("ls --json раскрыл значение")
	}
	fp := secProc(t, "", "get", "app/TOKEN", "--fingerprint")
	if strings.TrimSpace(fp.stdout) != tok["fingerprint"] {
		t.Errorf("отпечаток ls (%v) ≠ get --fingerprint (%s)", tok["fingerprint"], fp.stdout)
	}
	web := secProc(t, "", "ls", "web", "--json")
	if !strings.Contains(web.stdout, `"ref": "app/TOKEN"`) || !strings.Contains(web.stdout, `"fingerprint": "`+tok["fingerprint"].(string)) {
		t.Errorf("ссылка в ls --json: %s", web.stdout)
	}
	if g := secProc(t, "", "get", "web/TOKEN"); g.stdout != "value-two-456\n" {
		t.Errorf("get по ссылке: %+v", g)
	}
	if g := secProc(t, "", "get", "app/TOKEN", "--prev", "1"); g.stdout != "value-one-123\n" {
		t.Errorf("get --prev: %+v", g)
	}
}

// run --only не расшифровывает чужие значения: удаляем payload всех ключей,
// кроме нужного, — run --only и ls по-прежнему работают.
func TestRunOnlyDoesNotTouchOtherPayloads(t *testing.T) {
	dir := cliEnv(t)
	secProc(t, "need-me", "set", "app/NEED")
	secProc(t, "other", "set", "app/OTHER")
	big := filepath.Join(dir, "big.pem")
	os.WriteFile(big, bytes.Repeat([]byte("PEM"), 1000), 0o600)
	secProc(t, "", "set", "app/PEM", "--from-file", big)

	dropPayloadsExceptLen(t, len("need-me"))

	out := filepath.Join(dir, "env.txt")
	r := secProc(t, "", "run", "app", "--only", "NEED", "--", "sh", "-c", "printf %s \"$NEED\" > "+out)
	if data, _ := os.ReadFile(out); r.code != 0 || string(data) != "need-me" {
		t.Fatalf("run --only: %+v %q", r, data)
	}
	if r := secProc(t, "", "ls", "app", "--json"); r.code != 0 {
		t.Fatalf("ls без чужих payload: %+v", r)
	}
	if r := secProc(t, "", "get", "app/OTHER"); r.code == 0 || !strings.Contains(r.stderr, "нет в хранилище") {
		t.Fatalf("потерянный payload — явная ошибка: %+v", r)
	}
	if r := secProc(t, "", "run", "app", "--", "true"); r.code == 0 {
		t.Fatalf("run без --only должен упасть на потерянном payload, а не подставить пустое: %+v", r)
	}
}

// dropPayloadsExceptLen удаляет из базы все payload, кроме значения длины n
// (снаружи id не связан с ключом — различаем по размеру шифротекста:
// nonce 24 + тег 16 + значение).
func dropPayloadsExceptLen(t *testing.T, n int) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+os.Getenv("SEC_STORE")+"?mode=rw")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	res, err := db.Exec("DELETE FROM sec_payload WHERE length(blob) != ?", 24+16+n)
	if err != nil {
		t.Fatal(err)
	}
	if k, _ := res.RowsAffected(); k < 2 {
		t.Fatalf("удалено payload: %d", k)
	}
}

// sec migrate и обратно через CLI: JSON без значений, данные на месте.
func TestMigrateCLI(t *testing.T) {
	cliEnv(t)
	secProc(t, "", "set", "app/TOKEN") // пустой stdin — отказ, стор не создан
	if _, err := os.Stat(os.Getenv("SEC_STORE")); err == nil {
		t.Fatal("пустое значение не должно создавать стор")
	}
	secProc(t, "tok-123456789", "set", "app/TOKEN")
	r := secProc(t, "", "migrate", "--json")
	if r.code != 0 || !strings.Contains(r.stdout, `"changed": false`) {
		t.Fatalf("новый стор уже SQLite: %+v", r)
	}
	r = secProc(t, "", "migrate", "--to-v2", "--json")
	if r.code != 0 || !strings.Contains(r.stdout, `"to": "v2"`) || strings.Contains(r.stdout, "tok-123") {
		t.Fatalf("--to-v2: %+v", r)
	}
	secProc(t, "tok-after", "set", "app/AFTER")
	r = secProc(t, "", "migrate", "--json")
	if r.code != 0 || !strings.Contains(r.stdout, `"backup"`) {
		t.Fatalf("migrate: %+v", r)
	}
	if g := secProc(t, "", "get", "app/AFTER"); g.stdout != "tok-after\n" {
		t.Fatalf("после migrate: %+v", g)
	}
	if info := secProc(t, "", "info", "--json"); !strings.Contains(info.stdout, `"format": "v3"`) {
		t.Errorf("info: %s", info.stdout)
	}
}

// rekey с бэкендом env: новый ключ печатается, стор открывается им, слот
// убран; старый ключ больше не подходит.
func TestRekeyEnvCLI(t *testing.T) {
	cliEnv(t)
	secProc(t, "tok-123456789", "set", "app/TOKEN")
	r := secProc(t, "", "rekey")
	m := regexp.MustCompile(`(?m)^[0-9a-f]{64}$`).FindString(r.stdout)
	if r.code != 0 || m == "" {
		t.Fatalf("rekey: %+v", r)
	}
	if _, err := os.Stat(store.PendingKeyPath()); !os.IsNotExist(err) {
		t.Error("слот нового ключа должен быть убран после печати")
	}
	if g := secProc(t, "", "get", "app/TOKEN"); g.code == 0 {
		t.Fatal("старый SEC_KEY не должен открывать перешифрованный стор")
	}
	t.Setenv("SEC_KEY", m)
	if g := secProc(t, "", "get", "app/TOKEN"); g.stdout != "tok-123456789\n" {
		t.Fatalf("новый ключ: %+v", g)
	}
}

// scan не читает собственные файлы стора — ни по абсолютному пути, ни по
// относительному (раньше сравнивалась строка пути).
func TestScanSkipsOwnStoreFiles(t *testing.T) {
	dir := cliEnv(t)
	secProc(t, "scan-secret-value-123", "set", "app/TOKEN")
	f, err := os.CreateTemp(dir, "store.enc.*.tmp")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("scan-secret-value-123"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	os.WriteFile(filepath.Join(dir, "leak.txt"), []byte("x=scan-secret-value-123\n"), 0o600)
	t.Chdir(dir)
	r := secProc(t, "", "scan", ".", "--json")
	if !strings.Contains(r.stdout, "leak.txt") || strings.Contains(r.stdout, "store.enc") {
		t.Fatalf("scan: %s", r.stdout)
	}
}

func TestScanStoreNamedUserFiles(t *testing.T) {
	for _, base := range []string{"store.enc", "custom[store].db"} {
		t.Run(base, func(t *testing.T) {
			dir := cliEnv(t)
			t.Setenv("SEC_STORE", filepath.Join(dir, base))
			const marker = "synthetic-scan-marker-123"
			if r := secProc(t, marker, "set", "app/TOKEN"); r.code != 0 {
				t.Fatalf("fixture set: code %d", r.code)
			}
			// Legacy mode lets fixtures cover sidecar names without corrupting SQLite.
			if r := secProc(t, "", "migrate", "--to-v2"); r.code != 0 {
				t.Fatalf("fixture downgrade: code %d", r.code)
			}
			user := []string{base + ".env", base + ".txt", base + "-export.env", base + ".leftover.tmp"}
			own := []string{base, base + "-wal", base + "-shm", base + "-journal", base + ".lock", base + ".rekey-key", base + ".tmp",
				base + ".123.tmp", base + ".new-123.tmp", base + ".new-123.tmp-wal", base + ".new-123.tmp-shm",
				base + ".new-123.tmp-journal", base + ".v2-123.tmp", base + ".rekey-key.123.tmp",
				base + ".v2-20261024T120000.123456789Z.bak"}
			for _, name := range append(append([]string{}, user...), own[1:]...) {
				if err := os.WriteFile(filepath.Join(dir, name), []byte("TOKEN="+marker+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			t.Chdir(dir)
			for _, scan := range []struct {
				name  string
				paths []string
				count int
			}{
				{"explicit", user, len(user)},
				{"sidecars", own, 0},
				{"directory", []string{"."}, len(user)},
			} {
				t.Run(scan.name, func(t *testing.T) {
					if scan.name == "directory" {
						t.Setenv("SEC_STORE", "./"+base)
					}
					r := secProc(t, "", append([]string{"scan", "--json"}, scan.paths...)...)
					wantCode := 0
					if scan.count > 0 {
						wantCode = 1
					}
					env := decodeEnvelope(t, r.stdout)
					leaks := env["data"].(map[string]any)["leaks"].([]any)
					if r.code != wantCode || len(leaks) != scan.count {
						t.Errorf("scan: code=%d leaks=%d; want code=%d leaks=%d", r.code, len(leaks), wantCode, scan.count)
					}
					for _, l := range leaks {
						loc := l.(map[string]any)["loc"].(string)
						name, _, _ := strings.Cut(loc, ":")
						found := false
						for _, u := range user {
							found = found || filepath.Base(name) == u
						}
						if !found {
							t.Errorf("own artifact scanned: %s", name)
						}
					}
				})
			}
		})
	}
}
