package store

// Доступ к стору: Open — снимок только для чтения, Begin — транзакция записи
// (файловая блокировка + BEGIN IMMEDIATE до чтения каталога), Commit — её
// фиксация. Close обязателен перед exec, дочерними процессами и сетью:
// снимок SQLite держит читательскую блокировку и не даёт WAL сжаться.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/kaidstor/sec/internal/keyring"
)

const (
	formatNone = 0 // файла стора нет
	formatV2   = 2 // SECSTOR2
)

// lockWait — сколько ждать файловую блокировку записи, прежде чем отказать.
var lockWait = 10 * time.Second

type session struct {
	path    string
	key     []byte
	backend string
	format  int
	db      *sqlStore
	write   bool
	lock    *os.File
	closed  bool
	// committed — Commit с rekey прошёл, база закрыта, блокировка ждёт Close
	committed bool
	rekeyTo   []byte // Commit перешифрует всё этим ключом
	raw       []byte // исходный SECSTOR2 при записи (копия для migrate)
	pending   bool   // стор открыт ключом из слота незавершённого rekey
}

// testHook — точки останова для тестов прерывания (процесс-помощник
// завершается в них, как при падении). В обычной работе nil.
var testHook func(stage string)

func hook(stage string) {
	if testHook != nil {
		testHook(stage)
	}
}

var (
	liveMu sync.Mutex
	live   *session // открытый в процессе стор (не больше одного)
)

// Open загружает стор только для чтения. Значения в формате SQLite
// расшифровываются по требованию (Value.Load) из того же снимка. create=true
// разрешает инициализацию мастер-ключа при первом запуске.
func Open(create bool) (*Store, []byte, string, error) { return open(create, false) }

// Begin открывает стор для записи: эксклюзивная блокировка (совместима со
// старыми бинарями: тот же store.enc.lock), затем транзакция и только потом
// чтение — изменения между чтением и записью невозможны. Commit фиксирует,
// Close без Commit откатывает. Файла стора ещё нет — Commit создаст его в
// формате SQLite.
func Begin(create bool) (*Store, []byte, string, error) { return open(create, true) }

func open(create, write bool) (st *Store, key []byte, backend string, err error) {
	s := &session{path: Path(), write: write}
	liveMu.Lock()
	if live != nil {
		liveMu.Unlock()
		// два дескриптора одного файла в процессе: закрытие любого снимает
		// POSIX-блокировки SQLite на нём (fcntl владеет пара процесс+inode)
		return nil, nil, "", errors.New("стор уже открыт в этом процессе (внутренняя ошибка sec)")
	}
	live = s
	liveMu.Unlock()
	defer func() {
		if err != nil {
			s.close()
		}
	}()
	if write {
		if err := s.acquire(); err != nil {
			return nil, nil, "", err
		}
	}
	s.key, s.backend, err = keyring.Load(create)
	if err != nil {
		return nil, nil, "", err
	}
	for attempt := 0; ; attempt++ {
		st, err = s.load()
		if errors.Is(err, errNotSQLite) && attempt < 3 {
			continue
		}
		break
	}
	if err != nil {
		return nil, nil, "", err
	}
	st.sess = s
	return st, s.key, s.backend, nil
}

// load определяет формат по заголовку и читает стор. Файл открывается один
// раз: SECSTOR2 дочитывается из того же дескриптора, SQLite — закрывается до
// открытия драйвером.
func (s *session) load() (*Store, error) {
	if s.db != nil {
		s.db.close()
		s.db = nil
	}
	f, err := os.Open(s.path)
	if errors.Is(err, os.ErrNotExist) {
		s.format = formatNone
		return &Store{Version: storeVersion, Projects: map[string]map[string]Secret{}}, nil
	}
	if err != nil {
		return nil, err
	}
	head := make([]byte, len(sqliteMagic))
	n, _ := io.ReadFull(f, head)
	head = head[:n]
	if !bytes.Equal(head, []byte(sqliteMagic)) {
		var data []byte
		fi, serr := f.Stat()
		if serr == nil && fi.Size() >= int64(n) {
			data = make([]byte, fi.Size()) // стор в сотни МиБ — без второй копии при дочитывании
			copy(data, head)
			_, serr = io.ReadFull(f, data[n:])
		}
		f.Close()
		if serr != nil {
			return nil, serr
		}
		s.format = formatV2
		if s.write {
			s.raw = data
		}
		st, err := legacyParse(s.key, data)
		if errors.Is(err, errBadKey) {
			if pk := s.pendingKey(); pk != nil {
				if st, perr := legacyParse(pk, data); perr == nil {
					s.adoptPending(pk)
					return st, nil
				}
			}
		}
		return st, err
	}
	f.Close()
	s.format = formatV3
	d, err := openSQL(s.path, false)
	if err != nil {
		return nil, err
	}
	s.db = d
	if err := d.begin(s.write); err != nil {
		return nil, err
	}
	st, err := d.readCatalog(s.key)
	if errors.Is(err, errBadKey) {
		if pk := s.pendingKey(); pk != nil {
			if pst, perr := d.readCatalog(pk); perr == nil {
				s.adoptPending(pk)
				return pst, nil
			}
		}
	}
	return st, err
}

func (s *session) envPendingPath() string { return s.path + ".rekey-key" }

func (s *session) pendingKey() []byte {
	k, err := keyring.LoadPending(s.backend, s.envPendingPath())
	if err != nil {
		return nil
	}
	return k
}

// adoptPending — стор уже перешифрован ключом незавершённого rekey. Под
// блокировкой записи rekey доводится до конца (ключ становится основным),
// при чтении — только предупреждение: rekey в другом процессе может быть
// ещё в пути.
func (s *session) adoptPending(k []byte) {
	s.key = k
	s.pending = true
	loc := keyring.PendingLocation(s.backend, s.envPendingPath())
	if !s.write || s.backend == "env" {
		fmt.Fprintf(os.Stderr, "sec: незавершённая ротация мастер-ключа — стор открыт новым ключом из %s", loc)
		if s.backend == "env" {
			fmt.Fprintf(os.Stderr, "; перенеси его в SEC_KEY и удали файл\n")
		} else {
			fmt.Fprintf(os.Stderr, "; любая запись (или sec rekey) завершит ротацию\n")
		}
		return
	}
	hexKey := fmt.Sprintf("%x", k)
	if err := keyring.Promote(s.backend, hexKey); err != nil {
		fmt.Fprintf(os.Stderr, "sec: ротация ключа не завершена (%v) — ключ остаётся в %s\n", err, loc)
		return
	}
	if err := keyring.ClearPending(s.backend, s.envPendingPath()); err != nil {
		fmt.Fprintf(os.Stderr, "sec: ротация завершена, но слот %s не очищен: %v\n", loc, err)
		return
	}
	s.pending = false
	fmt.Fprintln(os.Stderr, "sec: незавершённая ротация мастер-ключа доведена до конца")
}

// acquire берёт эксклюзивную блокировку store.enc.lock с ограниченным
// ожиданием. Ошибка — отказ записи: без блокировки два процесса потеряли бы
// изменения друг друга (до SQLite lock-файл берут и старые бинари).
func (s *session) acquire() error {
	p := s.path + ".lock"
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("блокировка %s: %w", p, err)
	}
	deadline := time.Now().Add(lockWait)
	for {
		busy, err := flockTry(f)
		if err != nil {
			f.Close()
			return fmt.Errorf("блокировка %s: %w", p, err)
		}
		if !busy {
			s.lock = f
			return nil
		}
		if time.Now().After(deadline) {
			f.Close()
			return fmt.Errorf("хранилище занято другой командой sec дольше %s (блокировка %s)", lockWait, p)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (s *session) close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	var err error
	if s.db != nil {
		err = s.db.close()
		s.db = nil
	}
	if s.lock != nil {
		_ = flockUnlock(s.lock)
		_ = s.lock.Close()
		s.lock = nil
	}
	liveMu.Lock()
	if live == s {
		live = nil
	}
	liveMu.Unlock()
	return err
}

// Close закрывает снимок или откатывает незакоммиченную запись. Повторный
// вызов безопасен. Значения, не загруженные до Close, больше не читаются.
func (st *Store) Close() error {
	if st == nil || st.sess == nil {
		return nil
	}
	return st.sess.close()
}

// Commit фиксирует изменения транзакции записи и закрывает её (с RekeyTo —
// кроме блокировки, её снимает Close). После Commit стор годится только на
// чтение метаданных (имена, размеры, отпечатки).
func (st *Store) Commit() error {
	s := st.sess
	if s == nil || !s.write {
		return errors.New("стор открыт только на чтение (внутренняя ошибка sec)")
	}
	if s.closed || s.committed {
		return errors.New("транзакция стора уже закрыта (внутренняя ошибка sec)")
	}
	key := s.key
	if s.rekeyTo != nil {
		key = s.rekeyTo
	}
	var err error
	switch s.format {
	case formatNone:
		err = createStore(s.path, st, key)
	case formatV2:
		var data []byte
		if data, err = legacySeal(st, key); err == nil {
			err = writeDurable(s.path, data)
		}
	case formatV3:
		err = s.db.commit(st, key, s.rekeyTo != nil)
	}
	if err != nil {
		return err
	}
	s.key = key
	if s.rekeyTo != nil {
		// блокировка — до Close: rekey после коммита делает ключ основным и
		// чистит слот, а параллельный rekey между ними перешифровал бы стор
		// ключом, который этот процесс затем затрёт
		s.rekeyTo = nil
		s.committed = true
		if s.db == nil {
			return nil
		}
		err = s.db.close()
		s.db = nil
		return err
	}
	return s.close()
}

// PendingKeyUsed — стор открыт ключом из слота незавершённого rekey, а не
// основным (у бэкенда env это значит, что SEC_KEY ещё старый).
func (st *Store) PendingKeyUsed() bool { return st.sess != nil && st.sess.pending }

// Format — формат открытого стора: "none" (файла нет), "v2" (SECSTOR2) или
// "v3" (SQLite).
func (st *Store) Format() string {
	if st.sess == nil {
		return "none"
	}
	switch st.sess.format {
	case formatV2:
		return "v2"
	case formatV3:
		return "v3"
	}
	return "none"
}

// CloseAll — страховка для роутера: стор, который команда не закрыла,
// закрывается после неё (без этого следующая команда в том же процессе
// получила бы «стор уже открыт»).
func CloseAll() {
	liveMu.Lock()
	s := live
	liveMu.Unlock()
	if s != nil {
		s.close()
	}
}

// createStore создаёт новый стор SQLite рядом и переименовывает его на место:
// путь стора либо отсутствует, либо указывает на полностью готовую базу.
func createStore(p string, st *Store, key []byte) error {
	if _, err := os.Lstat(p); err == nil {
		return fmt.Errorf("%s появился во время записи — повтори команду", p)
	}
	tmp, err := buildSQLite(p, st, key)
	if err != nil {
		return err
	}
	return installDB(tmp, p)
}

// buildSQLite пишет стор целиком в новый файл SQLite рядом с p и возвращает
// его путь. Файл создаётся 0600 до драйвера: -wal и -shm SQLite заводит с
// правами основного файла.
func buildSQLite(p string, st *Store, key []byte) (string, error) {
	tmp, err := writeNew(filepath.Dir(p), filepath.Base(p)+".new-*.tmp", nil)
	if err != nil {
		return "", err
	}
	ok := false
	defer func() {
		if !ok {
			removeDB(tmp)
		}
	}()
	d, err := openSQL(tmp, false)
	if err != nil {
		return "", err
	}
	if err := d.create(key); err != nil {
		d.close()
		return "", err
	}
	if err := d.commit(st, key, true); err != nil {
		d.close()
		return "", err
	}
	if err := d.close(); err != nil {
		return "", err
	}
	// последнее закрытие чекпойнтит WAL в основной файл и удаляет -wal/-shm;
	// оставшийся -wal значит, что база не самодостаточна и переносить её нельзя
	if _, err := os.Lstat(tmp + "-wal"); err == nil {
		return "", errors.New("WAL новой базы не влился при закрытии — перенос отменён")
	}
	if err := syncFile(tmp); err != nil {
		return "", err
	}
	ok = true
	return tmp, nil
}

// installDB атомарно ставит готовую базу на место стора (сейчас там SECSTOR2
// или ничего). Оставшиеся от прежней базы -wal/-shm/-journal удаляются до
// rename: SQLite применил бы чужой журнал к новой базе.
func installDB(tmp, p string) error {
	if err := removeSidecars(p); err != nil {
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		return err
	}
	return syncDir(filepath.Dir(p))
}

func removeSidecars(p string) error {
	for _, sfx := range []string{"-wal", "-shm", "-journal"} {
		if err := os.Remove(p + sfx); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("не удалось убрать устаревший %s: %w", p+sfx, err)
		}
	}
	return nil
}

// CreateTemp подставляет десятичный uint32; произвольный суффикс здесь
// скрыл бы от scan пользовательские файлы вроде store.enc.export.tmp.
var storeTempSuffix = regexp.MustCompile(`^\.(new-|v2-|rekey-key\.)?[0-9]{1,10}\.tmp$`)

func IsOwnFile(p string) bool {
	sp := filepath.Clean(Path())
	p = filepath.Clean(p)
	base, name := filepath.Base(sp), filepath.Base(p)
	suffix, ok := strings.CutPrefix(name, base)
	if !ok {
		return false
	}
	switch suffix {
	case "", "-wal", "-shm", "-journal", ".lock", ".rekey-key", ".tmp":
	default:
		staging := suffix
		if strings.HasPrefix(staging, ".new-") {
			for _, sidecar := range []string{"-wal", "-shm", "-journal"} {
				if s, ok := strings.CutSuffix(staging, sidecar); ok {
					staging = s
					break
				}
			}
		}
		if !storeTempSuffix.MatchString(staging) {
			stamp := strings.TrimSuffix(strings.TrimPrefix(suffix, ".v2-"), ".bak")
			const layout = "20060102T150405.000000000Z"
			ts, err := time.Parse(layout, stamp)
			if err != nil || suffix != ".v2-"+ts.Format(layout)+".bak" {
				return false
			}
		}
	}
	a, err := os.Stat(filepath.Dir(p))
	if err != nil {
		return false
	}
	b, err := os.Stat(filepath.Dir(sp))
	return err == nil && os.SameFile(a, b)
}

func syncFile(p string) error {
	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func removeDB(p string) {
	for _, sfx := range []string{"", "-wal", "-shm", "-journal"} {
		os.Remove(p + sfx)
	}
}
