package store

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kaidstor/sec/internal/keyring"
)

const marker = "SYNTHETIC-MARKER-7f3a"

// sample — модель со всеми формами данных: текст, бинарь, пустое значение,
// большое значение без enc, история, redo, мета, ссылка, наследование,
// проект-заглушка с null.
func sample() *portableStore {
	big := strings.Repeat("x"+marker, 300_000) // ~6 МиБ без enc
	bin := base64.StdEncoding.EncodeToString([]byte("\x00\x01binary\xff" + marker))
	return &portableStore{
		Version: storeVersion,
		Projects: map[string]map[string]portableSecret{
			"app-" + marker: {
				"TOKEN_" + marker: {Value: sp("tok-" + marker), UpdatedAt: "2026-01-03T00:00:00Z",
					History:   []portableVersion{{Value: sp("old2-" + marker), UpdatedAt: "2026-01-02T00:00:00Z"}, {Value: sp("old1-" + marker), UpdatedAt: "2026-01-01T00:00:00Z"}},
					RedoStack: []portableVersion{{Value: sp("fwd-" + marker), UpdatedAt: "2026-01-04T00:00:00Z"}},
					Meta:      &Meta{Note: "note " + marker, Kind: "apikey", RotateEvery: "90d"}},
				"CERT":  {Value: sp(bin), Enc: EncB64, UpdatedAt: "2026-02-01T00:00:00Z", Meta: &Meta{Kind: "file", Filename: marker + ".p12", FileMode: "0644"}},
				"EMPTY": {Value: sp(""), UpdatedAt: "2026-02-02T00:00:00Z", Meta: &Meta{}},
				"BIG":   {Value: sp(big), UpdatedAt: "2026-02-03T00:00:00Z"},
				"LINK":  {Value: sp(""), Ref: "base/SHARED", UpdatedAt: "2026-02-04T00:00:00Z"},
			},
			"base":  {"SHARED": {Value: sp("shared-" + marker), UpdatedAt: "2026-01-05T00:00:00Z"}},
			"empty": nil,
		},
		Extends: map[string][]string{"app-" + marker: {"base"}},
	}
}

func newV3(t *testing.T, ps *portableStore) {
	t.Helper()
	st, _, _, err := Begin(true)
	if err != nil {
		t.Fatal(err)
	}
	src := fromPortable(ps)
	st.Projects, st.Extends = src.Projects, src.Extends
	if err := st.Commit(); err != nil {
		t.Fatal(err)
	}
}

func openRead(t *testing.T) *Store {
	t.Helper()
	st, _, _, err := Open(false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func mustSame(t *testing.T, want *portableStore, got *Store) {
	t.Helper()
	same, err := samePortable(fromPortable(want), got)
	if err != nil {
		t.Fatal(err)
	}
	if !same {
		a, _ := MarshalPortable(fromPortable(want))
		b, _ := MarshalPortable(got)
		t.Fatalf("логическая модель разошлась:\nwant %d байт\ngot  %d байт", len(a), len(b))
	}
}

func TestNewStoreIsSQLiteAndRoundtrips(t *testing.T) {
	testEnv(t)
	newV3(t, sample())
	st := openRead(t)
	if st.Format() != "v3" {
		t.Fatalf("новый стор должен быть SQLite, а он %s", st.Format())
	}
	mustSame(t, sample(), st)
	for _, p := range []string{Path(), Path() + "-wal", Path() + "-shm"} {
		if fi, err := os.Stat(p); err == nil && fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: права %o, ожидались 600", filepath.Base(p), fi.Mode().Perm())
		}
	}
}

// Значения читаются по одному: get одного ключа не трогает чужие payload,
// а размеры и отпечатки берутся из каталога. Удаляем все payload, кроме
// нужного, — get по-прежнему работает, метаданные всех ключей тоже.
func TestLazyReadTouchesOnlyRequestedPayload(t *testing.T) {
	key := testEnv(t)
	newV3(t, sample())
	st := openRead(t)
	want := st.Projects["base"]["SHARED"].Val
	wantFP := Fingerprint(key, "shared-"+marker)
	st.Close()

	d, err := openSQL(Path(), false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.conn.ExecContext(bg, "DELETE FROM sec_payload WHERE id != ?", want.id); err != nil {
		t.Fatal(err)
	}
	d.close()

	st = openRead(t)
	sec, _, _, ok := st.Lookup("app-"+marker, "LINK")
	if !ok || txt(sec.Val) != "shared-"+marker || sec.Val.Fingerprint(key) != wantFP {
		t.Fatal("значение по ссылке не прочиталось из единственного оставшегося payload")
	}
	big := st.Projects["app-"+marker]["BIG"]
	if big.Val.Chars() != 300_000*(1+len(marker)) || big.Val.Fingerprint(key) == "" {
		t.Error("длина/отпечаток должны браться из каталога без payload")
	}
	if cert := st.Projects["app-"+marker]["CERT"]; cert.Val.DecodedLen() != len("\x00\x01binary\xff"+marker) {
		t.Errorf("DecodedLen бинарного = %d", cert.Val.DecodedLen())
	}
	if _, err := big.Val.Load(); err == nil || !strings.Contains(err.Error(), "нет в хранилище") {
		t.Fatalf("удалённый payload должен давать явную ошибку, а не пустое значение: %v", err)
	}
	if _, err := MarshalPortable(st); err == nil {
		t.Fatal("бэкап при потерянном payload должен отказать")
	}
}

func TestTamperedPayloadFails(t *testing.T) {
	testEnv(t)
	newV3(t, sample())
	st := openRead(t)
	a := st.Projects["base"]["SHARED"].Val
	b := st.Projects["app-"+marker]["TOKEN_"+marker].Val
	st.Close()

	d, err := openSQL(Path(), false)
	if err != nil {
		t.Fatal(err)
	}
	// подмена: строке A — шифротекст B (оба валидны под своим AAD)
	if _, err := d.conn.ExecContext(bg, "UPDATE sec_payload SET blob = (SELECT blob FROM sec_payload WHERE id = ?) WHERE id = ?", b.id, a.id); err != nil {
		t.Fatal(err)
	}
	// порча байта в C
	c := ""
	if err := d.conn.QueryRowContext(bg, "SELECT id FROM sec_payload WHERE id NOT IN (?, ?) LIMIT 1", a.id, b.id).Scan(&c); err != nil {
		t.Fatal(err)
	}
	if _, err := d.conn.ExecContext(bg, "UPDATE sec_payload SET blob = CAST(substr(blob, 1, 30) || x'00' || substr(blob, 32) AS BLOB) WHERE id = ?", c); err != nil {
		t.Fatal(err)
	}
	d.close()

	st = openRead(t)
	if _, err := st.Projects["base"]["SHARED"].Val.Load(); err == nil {
		t.Fatal("переставленный payload должен не расшифроваться")
	}
	if _, err := st.Projects["app-"+marker]["TOKEN_"+marker].Val.Load(); err != nil {
		t.Fatalf("нетронутый payload должен читаться: %v", err)
	}
	if _, err := MarshalPortable(st); err == nil {
		t.Fatal("экспорт стора с испорченными payload должен отказать")
	}
}

func dirContains(t *testing.T, dir, needle string) []string {
	t.Helper()
	var hits []string
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		if bytes.Contains(data, []byte(needle)) {
			hits = append(hits, e.Name())
		}
	}
	return hits
}

// Ни значения, ни имена проектов/ключей, ни заметки, ни имена файлов не
// попадают на диск открытым текстом: ни в базу, ни в WAL (читатель держит
// снимок — WAL не вливается), ни в файлы сборки миграции.
func TestNoPlaintextOnDisk(t *testing.T) {
	key := testEnv(t)
	dir := filepath.Dir(Path())
	writeLegacy(t, key, sample())

	var during []string
	testHook = func(stage string) {
		if stage == "migrate:built" {
			during = dirContains(t, dir, marker)
		}
	}
	defer func() { testHook = nil }()
	if _, err := Migrate(); err != nil {
		t.Fatal(err)
	}
	if len(during) > 0 {
		t.Errorf("маркер открытым текстом во время миграции: %v", during)
	}

	// второе соединение держит снимок, чтобы запись осела в -wal
	reader, err := openSQL(Path(), false)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.begin(false); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.readCatalog(key); err != nil {
		t.Fatal(err)
	}
	st, _, _, err := Begin(false)
	if err != nil {
		t.Fatal(err)
	}
	Put(st.Project("new-"+marker), "K_"+marker, "v-"+marker)
	if err := st.Commit(); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(Path() + "-wal"); err != nil || fi.Size() == 0 {
		t.Fatalf("ожидался непустой -wal при живом читателе: %v", err)
	}
	if hits := dirContains(t, dir, marker); len(hits) > 0 {
		t.Errorf("маркер открытым текстом в файлах стора: %v", hits)
	}
	reader.close()
}

// Полный круг: SECSTOR2 → SQLite → новые записи → SECSTOR2. Обратная миграция
// уносит записанное после перехода, старый формат читается как прежде, а
// старый бинарь (проверка magic SECSTOR2) на базе SQLite отказывает.
func TestMigrateRoundtripKeepsNewWrites(t *testing.T) {
	key := testEnv(t)
	writeLegacy(t, key, sample())
	orig, _ := os.ReadFile(Path())

	st := openRead(t)
	if st.Format() != "v2" {
		t.Fatalf("формат %s, ожидался v2", st.Format())
	}
	mustSame(t, sample(), st)
	st.Close()
	if after, _ := os.ReadFile(Path()); !bytes.Equal(after, orig) {
		t.Fatal("чтение SECSTOR2 не должно менять файл")
	}

	res, err := Migrate()
	if err != nil {
		t.Fatal(err)
	}
	if res.From != "v2" || res.To != "v3" || res.Keys != 6 || res.Values != 9 {
		t.Errorf("результат миграции: %+v", res)
	}
	bak, err := os.ReadFile(res.Backup)
	if err != nil || !bytes.Equal(bak, orig) {
		t.Fatalf("копия прежнего файла должна совпасть байт-в-байт: %v", err)
	}
	if fi, _ := os.Stat(res.Backup); fi.Mode().Perm() != 0o600 {
		t.Errorf("права копии %o", fi.Mode().Perm())
	}
	db, _ := os.ReadFile(Path())
	if _, err := legacyDecrypt(key, db); err == nil || !strings.Contains(err.Error(), "не похоже") {
		t.Fatalf("старый бинарь должен отказать на SQLite-базе: %v", err)
	}
	if again, err := Migrate(); err != nil || again.From != "v3" {
		t.Fatalf("повторная миграция — no-op: %+v %v", again, err)
	}

	// записи после перехода
	st, _, _, err = Begin(false)
	if err != nil {
		t.Fatal(err)
	}
	Put(st.Project("base"), "SHARED", "shared-v2")
	Put(st.Project("after"), "NEW", "after-cutover")
	if err := st.Commit(); err != nil {
		t.Fatal(err)
	}
	want := sample()
	want.Projects["base"]["SHARED"] = portableSecret{} // заполним из стора ниже
	st = openRead(t)
	cur, err := toPortable(st)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	if deref(cur.Projects["after"]["NEW"].Value) != "after-cutover" || deref(cur.Projects["base"]["SHARED"].History[0].Value) != "shared-"+marker {
		t.Fatal("новые записи не на месте")
	}

	if _, err := MigrateToV2(); err != nil {
		t.Fatal(err)
	}
	for _, sfx := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(Path() + sfx); err == nil {
			t.Errorf("после --to-v2 остался %s", sfx)
		}
	}
	data, _ := os.ReadFile(Path())
	back, err := legacyParse(key, data) // ровно то, что делает старый бинарь
	if err != nil {
		t.Fatal(err)
	}
	mustSame(t, cur, back)
	if _, err := os.Stat(res.Backup); err != nil {
		t.Error("копия прежнего формата не должна удаляться обратной миграцией")
	}
}

func TestPortableRefusesUnknownForms(t *testing.T) {
	ps := sample()
	data, err := MarshalPortable(fromPortable(ps))
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParsePortable(data)
	if err != nil {
		t.Fatal(err)
	}
	mustSame(t, ps, back)
	for _, bad := range []string{
		`{"version": 3, "projects": {}}`,
		`{"version": 2, "objects": {"p": {}}}`,
		`{"version": 2, "projects": null}`,
		`[]`,
	} {
		if _, err := ParsePortable([]byte(bad)); err == nil {
			t.Errorf("ParsePortable(%s) должен отказать", bad)
		}
	}
}

// Отсутствующее или null value — не пустой секрет: раньше такая запись (в
// том числе с чужой ссылкой на локальный payload) молча становилась "".
// Законный value:"" и ссылки в форме, которую всегда писал sec, проходят.
func TestPortableRequiresValue(t *testing.T) {
	for _, bad := range []string{
		`{"version":2,"projects":{"app":{"K":{"payloadRef":"local-only-id"}}}}`,
		`{"version":2,"projects":{"app":{"K":{"value":null,"updatedAt":"t"}}}}`,
		`{"version":2,"projects":{"app":{"K":null}}}`,
		`{"version":2,"projects":{"app":{"K":{"value":"x","history":[{"updatedAt":"t"}]}}}}`,
		`{"version":2,"projects":{"app":{"K":{"value":"x","redo":[null]}}}}`,
		`{"version":2,"projects":{"app":{"K":{"value":"","id":"0a1b2c"}}}}`,
		`{"version":2,"projects":{"app":{"K":{"value":"x","history":[{"value":"","id":"0a1b2c"}]}}}}`,
		`{"version":2,"projects":{"app":{"K":{"value":"","payloadRef":"local-only-id"}}}}`,
		`{"version":2,"projects":{"app":{"K":{"value":"x","history":[{"value":"","payloadRef":"local-only-id"}]}}}}`,
		`{"version":2,"projects":{"app":{"K":{"value":"x","redo":[{"value":"","payloadRef":"local-only-id"}]}}}}`,
	} {
		if _, err := ParsePortable([]byte(bad)); err == nil {
			t.Errorf("ParsePortable(%s) должен отказать", bad)
		}
	}
	ok := `{"version":2,"projects":{"app":{` +
		`"EMPTY":{"value":"","updatedAt":"t1"},` +
		`"K":{"value":"v2","updatedAt":"t2","history":[{"value":"","updatedAt":"t0"}],"redo":[{"value":"v3","updatedAt":"t3"}],"unknownField":1},` +
		`"L":{"value":"","ref":"app/K","updatedAt":"t4"}},` +
		`"empty":null}}`
	st, err := ParsePortable([]byte(ok))
	if err != nil {
		t.Fatal(err)
	}
	app := st.Projects["app"]
	if txt(app["EMPTY"].Val) != "" || txt(app["K"].History[0].Val) != "" || txt(app["K"].RedoStack[0].Val) != "v3" || app["L"].Ref != "app/K" {
		t.Fatalf("совместимая форма разобрана неверно: %+v", app)
	}
}

// Commit с rekey держит блокировку записи до Close: ключ в бэкенде и слот
// обновляются под ней. Раньше Commit отпускал её сразу, и параллельный rekey
// успевал перешифровать стор ключом, который первый затем затирал.
func TestRekeyCommitKeepsLockUntilClose(t *testing.T) {
	for _, format := range []string{"v2", "v3"} {
		t.Run(format, func(t *testing.T) {
			key := testEnv(t)
			if format == "v2" {
				writeLegacy(t, key, sample())
			} else {
				newV3(t, sample())
			}
			locked := func() bool {
				t.Helper()
				f, err := os.OpenFile(Path()+".lock", os.O_CREATE|os.O_RDWR, 0o600)
				if err != nil {
					t.Fatal(err)
				}
				defer f.Close()
				busy, err := flockTry(f)
				if err != nil {
					t.Fatal(err)
				}
				if !busy {
					flockUnlock(f)
				}
				return busy
			}

			w, _, _, err := Begin(false)
			if err != nil {
				t.Fatal(err)
			}
			Put(w.Project("app"), "PLAIN", "x")
			if err := w.Commit(); err != nil {
				t.Fatal(err)
			}
			if locked() {
				t.Fatal("обычный Commit должен отпускать блокировку сразу")
			}

			w, _, _, err = Begin(false)
			if err != nil {
				t.Fatal(err)
			}
			_, newKey, _ := keyring.NewHex()
			if err := w.RekeyTo(newKey); err != nil {
				t.Fatal(err)
			}
			if err := w.Commit(); err != nil {
				t.Fatal(err)
			}
			if !locked() {
				t.Fatal("после Commit с rekey блокировка должна держаться до Close")
			}
			if err := w.Commit(); err == nil {
				t.Fatal("повторный Commit после rekey должен отказать")
			}
			w.Close()
			if locked() {
				t.Fatal("Close должен отпустить блокировку")
			}
		})
	}
}

// Merge не превращает входящую ссылку в пустое собственное значение и
// переносит новый ключ вместе с историей и redo (раньше терялись).
func TestMergeKeepsIncomingRefAndHistory(t *testing.T) {
	dst := fromPortable(&portableStore{Projects: map[string]map[string]portableSecret{
		"app": {"OWN": {Value: sp("local")}},
	}})
	src := fromPortable(&portableStore{Projects: map[string]map[string]portableSecret{
		"app": {
			"LINK": {Ref: "base/X"},
			"OWN":  {Ref: "base/X"},
			"HIST": {Value: sp("h2"), History: []portableVersion{{Value: sp("h1"), UpdatedAt: "t1"}}, RedoStack: []portableVersion{{Value: sp("h3"), UpdatedAt: "t3"}}},
		},
	}})
	added, updated, skipped := Merge(dst, src)
	if l := dst.Projects["app"]["LINK"]; l.Ref != "base/X" {
		t.Errorf("входящая ссылка стала собственным значением: %+v", l)
	}
	if h := dst.Projects["app"]["HIST"]; len(h.History) != 1 || len(h.RedoStack) != 1 {
		t.Error("история и redo нового ключа должны переехать")
	}
	if o := dst.Projects["app"]["OWN"]; o.Ref != "" || txt(o.Val) != "local" {
		t.Error("ссылка поверх собственного значения должна быть пропущена")
	}
	if added != 2 || updated != 0 || len(skipped) != 1 || skipped[0] != "app/OWN" {
		t.Errorf("added=%d updated=%d skipped=%v", added, updated, skipped)
	}
}

// ---------------------------------------------------------------------------
// Межпроцессные сценарии: тест перезапускает свой бинарь помощником.
// ---------------------------------------------------------------------------

func TestHelperProcess(t *testing.T) {
	mode := os.Getenv("SEC_TEST_HELPER")
	if mode == "" {
		t.Skip("только как процесс-помощник")
	}
	if stage := os.Getenv("SEC_TEST_CRASH"); stage != "" {
		testHook = func(s string) {
			if s == stage {
				os.Exit(77) // «падение»: без defer, без очистки
			}
		}
	}
	if ms := os.Getenv("SEC_TEST_LOCKWAIT_MS"); ms != "" {
		n, _ := strconv.Atoi(ms)
		lockWait = time.Duration(n) * time.Millisecond
	}
	err := helper(mode)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

func helper(mode string) error {
	switch mode {
	case "migrate":
		_, err := Migrate()
		return err
	case "downgrade":
		_, err := MigrateToV2()
		return err
	case "put", "rm", "incr":
		st, _, _, err := Begin(false)
		if err != nil {
			return err
		}
		defer st.Close()
		switch mode {
		case "put":
			Put(st.Project("app"), os.Getenv("SEC_TEST_KEY"), "v-"+os.Getenv("SEC_TEST_KEY"))
		case "rm":
			delete(st.Projects["base"], "SHARED")
		case "incr":
			n, _ := strconv.Atoi(txt(st.Projects["count"]["N"].Val))
			Put(st.Project("count"), "N", strconv.Itoa(n+1))
			Put(st.Project("count"), "W"+os.Getenv("SEC_TEST_KEY"), "x")
		}
		return st.Commit()
	case "hold-lock":
		st, _, _, err := Begin(false)
		if err != nil {
			return err
		}
		fmt.Println("locked")
		time.Sleep(3 * time.Second)
		return st.Close()
	case "hold-sqlite":
		d, err := openSQL(Path(), false)
		if err != nil {
			return err
		}
		if err := d.begin(true); err != nil {
			return err
		}
		fmt.Println("locked")
		time.Sleep(8 * time.Second)
		return d.close()
	}
	return fmt.Errorf("неизвестный режим %q", mode)
}

func helperCmd(mode string, env ...string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$")
	cmd.Env = append(append(os.Environ(), "SEC_TEST_HELPER="+mode), env...)
	return cmd
}

func runHelper(t *testing.T, mode string, env ...string) (int, string) {
	t.Helper()
	out, err := helperCmd(mode, env...).CombinedOutput()
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), string(out)
	}
	if err != nil {
		t.Fatal(err)
	}
	return 0, string(out)
}

// Процесс падает в каждой точке миграции: на месте стора всегда либо
// прежний SECSTOR2, либо полностью готовая база, и модель не меняется.
func TestInterruptedMigration(t *testing.T) {
	for _, c := range []struct{ stage, want string }{
		{"migrate:built", "v2"},
		{"migrate:backup", "v2"},
		{"migrate:installed", "v3"},
	} {
		t.Run(c.stage, func(t *testing.T) {
			key := testEnv(t)
			writeLegacy(t, key, sample())
			if code, out := runHelper(t, "migrate", "SEC_TEST_CRASH="+c.stage); code != 77 {
				t.Fatalf("помощник не упал в %s: %d %s", c.stage, code, out)
			}
			st := openRead(t)
			if st.Format() != c.want {
				t.Fatalf("после падения в %s формат %s, ожидался %s", c.stage, st.Format(), c.want)
			}
			mustSame(t, sample(), st)
			st.Close()
			if c.want == "v2" { // повтор после сбоя доводит дело
				if _, err := Migrate(); err != nil {
					t.Fatal(err)
				}
				mustSame(t, sample(), openRead(t))
			}
		})
	}
	t.Run("downgrade:staged", func(t *testing.T) {
		testEnv(t)
		newV3(t, sample())
		if code, out := runHelper(t, "downgrade", "SEC_TEST_CRASH=downgrade:staged"); code != 77 {
			t.Fatalf("помощник не упал: %d %s", code, out)
		}
		st := openRead(t)
		if st.Format() != "v3" {
			t.Fatalf("формат %s", st.Format())
		}
		mustSame(t, sample(), st)
	})
}

// Падение посреди транзакции записи (payload уже вставлены, COMMIT нет) не
// оставляет следов: стор прежний, следующая запись проходит.
func TestInterruptedCommit(t *testing.T) {
	testEnv(t)
	newV3(t, sample())
	if code, out := runHelper(t, "put", "SEC_TEST_KEY=CRASHED", "SEC_TEST_CRASH=sqlite:before-commit"); code != 77 {
		t.Fatalf("помощник не упал: %d %s", code, out)
	}
	st := openRead(t)
	mustSame(t, sample(), st)
	st.Close()
	if code, out := runHelper(t, "put", "SEC_TEST_KEY=AFTER"); code != 0 {
		t.Fatalf("запись после сбоя: %s", out)
	}
	if _, ok := openRead(t).Projects["app"]["AFTER"]; !ok {
		t.Fatal("запись после сбоя не легла")
	}
}

// Читатель держит снимок, писатель в другом процессе удаляет ключ (его payload
// уходит в GC той же транзакцией) — читатель всё равно дочитывает значение.
func TestReaderSnapshotSurvivesWriterGC(t *testing.T) {
	testEnv(t)
	newV3(t, sample())
	st := openRead(t)
	shared := st.Projects["base"]["SHARED"].Val
	if code, out := runHelper(t, "rm"); code != 0 {
		t.Fatalf("писатель: %s", out)
	}
	if v, err := shared.Load(); err != nil || v != "shared-"+marker {
		t.Fatalf("снимок читателя должен видеть удалённый payload: %q %v", v, err)
	}
	st.Close()
	if _, ok := openRead(t).Projects["base"]["SHARED"]; ok {
		t.Fatal("после закрытия снимка удаление должно быть видно")
	}
	d, err := openSQL(Path(), false)
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	var n int
	if err := d.conn.QueryRowContext(bg, "SELECT count(*) FROM sec_payload WHERE id = ?", shared.id).Scan(&n); err != nil || n != 0 {
		t.Fatalf("payload удалённого ключа должен быть собран: n=%d %v", n, err)
	}
}

// Параллельные процессы читают-меняют-пишут общий счётчик: ни одно
// изменение не теряется (транзакция начинается до чтения).
func TestConcurrentWritersNoLostUpdates(t *testing.T) {
	testEnv(t)
	st, _, _, err := Begin(true)
	if err != nil {
		t.Fatal(err)
	}
	Put(st.Project("count"), "N", "0")
	if err := st.Commit(); err != nil {
		t.Fatal(err)
	}
	const n = 8
	cmds := make([]*exec.Cmd, n)
	outs := make([]bytes.Buffer, n)
	for i := range cmds {
		cmds[i] = helperCmd("incr", "SEC_TEST_KEY="+strconv.Itoa(i))
		cmds[i].Stdout, cmds[i].Stderr = &outs[i], &outs[i]
		if err := cmds[i].Start(); err != nil {
			t.Fatal(err)
		}
	}
	for i, c := range cmds {
		if err := c.Wait(); err != nil {
			t.Fatalf("писатель %d: %v %s", i, err, outs[i].String())
		}
	}
	got := openRead(t).Projects["count"]
	if txt(got["N"].Val) != strconv.Itoa(n) || len(got) != n+1 || len(got["N"].History) != 5 {
		t.Fatalf("счётчик %s, ключей %d, история %d — изменения потеряны", txt(got["N"].Val), len(got), len(got["N"].History))
	}
}

// Занятость видна и ограничена по времени: и чужая блокировка sec, и чужая
// транзакция записи SQLite.
func TestBusyIsBoundedAndVisible(t *testing.T) {
	testEnv(t)
	newV3(t, sample())

	hold := helperCmd("hold-lock")
	stdout, _ := hold.StdoutPipe()
	if err := hold.Start(); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 6)
	if _, err := stdout.Read(buf); err != nil {
		t.Fatal(err)
	}
	old := lockWait
	lockWait = 300 * time.Millisecond
	start := time.Now()
	_, _, _, err := Begin(false)
	lockWait = old
	if err == nil || !strings.Contains(err.Error(), "занято") || time.Since(start) > 2*time.Second {
		t.Fatalf("ожидался быстрый отказ «занято»: %v за %s", err, time.Since(start))
	}
	CloseAll()
	hold.Wait()

	holdDB := helperCmd("hold-sqlite")
	stdout, _ = holdDB.StdoutPipe()
	if err := holdDB.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := stdout.Read(buf); err != nil {
		t.Fatal(err)
	}
	start = time.Now()
	_, _, _, err = Begin(false)
	if err == nil || !strings.Contains(err.Error(), "занято") || time.Since(start) > 7*time.Second {
		t.Fatalf("ожидался отказ «занято» за busy_timeout: %v за %s", err, time.Since(start))
	}
	CloseAll()
	holdDB.Wait()
}

// Граница rekey для бэкенда env: новый ключ в слоте, стор перешифрован, а
// SEC_KEY ещё старый (упали до печати ключа) — стор открывается ключом из
// слота. Упали до коммита — открывается старым, слот лишний.
func TestRekeyBoundaryRecoverable(t *testing.T) {
	for _, format := range []string{"v2", "v3"} {
		t.Run(format, func(t *testing.T) {
			key := testEnv(t)
			if format == "v2" {
				writeLegacy(t, key, sample())
			} else {
				newV3(t, sample())
			}
			// сбой до коммита
			k3, _, _ := keyring.NewHex()
			if err := keyring.SavePending("env", k3, PendingKeyPath()); err != nil {
				t.Fatal(err)
			}
			st := openRead(t)
			if st.PendingKeyUsed() {
				t.Fatal("стор цел под старым ключом — слот не нужен")
			}
			st.Close()

			// сбой после коммита
			newHex, newKey, _ := keyring.NewHex()
			if err := keyring.SavePending("env", newHex, PendingKeyPath()); err != nil {
				t.Fatal(err)
			}
			w, _, _, err := Begin(false)
			if err != nil {
				t.Fatal(err)
			}
			if err := w.RekeyTo(newKey); err != nil {
				t.Fatal(err)
			}
			if err := w.Commit(); err != nil {
				t.Fatal(err)
			}
			w.Close()
			st = openRead(t) // SEC_KEY всё ещё старый
			if !st.PendingKeyUsed() {
				t.Fatal("стор должен открыться ключом из слота")
			}
			mustSame(t, sample(), st)
			st.Close()
			t.Setenv("SEC_KEY", newHex)
			mustSame(t, sample(), openRead(t))
			t.Setenv("SEC_KEY", hex.EncodeToString(key))
			if err := keyring.ClearPending("env", PendingKeyPath()); err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := Open(false); err == nil {
				t.Fatal("без слота старый ключ не должен открывать перешифрованный стор")
			}
		})
	}
}

func TestOpenRejectsGarbageAndForeignSQLite(t *testing.T) {
	testEnv(t)
	junk := make([]byte, 64)
	rand.Read(junk)
	os.MkdirAll(filepath.Dir(Path()), 0o700)
	os.WriteFile(Path(), junk, 0o600)
	if _, _, _, err := Open(false); err == nil {
		t.Fatal("мусор не должен открываться")
	}
	os.Remove(Path())
	d, err := openSQL(Path(), true)
	if err != nil {
		t.Fatal(err)
	}
	d.conn.ExecContext(bg, "CREATE TABLE x(a)")
	d.close()
	if _, _, _, err := Open(false); err == nil || !strings.Contains(err.Error(), "не хранилище sec") {
		t.Fatalf("чужая SQLite-база должна отвергаться: %v", err)
	}
	if _, _, _, err := Begin(false); err == nil {
		t.Fatal("запись в чужую базу должна отвергаться")
	}
}
