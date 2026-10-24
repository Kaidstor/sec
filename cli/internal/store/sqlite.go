package store

// SECSTOR3 — локальная SQLite (modernc.org/sqlite, без CGO), шифрование — в
// приложении до передачи данных драйверу. Таблицы:
//
//	sec_meta(name, value)    store_id — случайный UUID стора (открыто)
//	sec_catalog(id=1, blob)  весь каталог одним AEAD-блобом: имена проектов и
//	                         ключей, ссылки, наследование, метаданные, даты,
//	                         id payload и сводки версий (длина, HMAC)
//	sec_payload(id, blob)    по строке на значение версии; id случайный,
//	                         неизменяемый, ни с именем, ни с проектом не связан
//
// Блоб = nonce(24) || XChaCha20-Poly1305. AAD каталога —
// "SECSTOR3\0catalog\0"+store_id, payload — "SECSTOR3\0payload\0"+store_id+
// "\0"+id: подмена payload между строками или сторами не расшифруется, а
// расшифрованное сверяется с длиной и HMAC из каталога. Видны снаружи только
// структура: число и размеры payload, размер каталога, время изменения.
//
// Чтение — снимок (BEGIN + SELECT каталога), payload читаются в том же
// снимке; запись — BEGIN IMMEDIATE до чтения каталога. Новый payload —
// всегда новый id, старые удаляются той же транзакцией, когда на них не
// осталось ссылок: читатель со старым снимком их ещё видит (WAL).

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	sqlite "modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

const (
	sqliteMagic = "SQLite format 3\x00"
	formatV3    = 3          // PRAGMA user_version
	appID       = 0x53454333 // PRAGMA application_id, "SEC3"
	busyMillis  = 5000
	aadPrefix   = "SECSTOR3\x00"
)

const schemaSQL = `
CREATE TABLE sec_meta (name TEXT PRIMARY KEY, value BLOB NOT NULL) STRICT;
CREATE TABLE sec_catalog (id INTEGER PRIMARY KEY CHECK (id = 1), blob BLOB NOT NULL) STRICT;
CREATE TABLE sec_payload (id TEXT PRIMARY KEY, blob BLOB NOT NULL) STRICT;
`

var bg = context.Background()

type sqlStore struct {
	db   *sql.DB
	conn *sql.Conn
	key  []byte // ключ, которым читаются каталог и payload этого снимка
	sid  []byte
	inTx bool
}

type catVersion struct {
	ID        string    `json:"id,omitempty"` // "" — пустое значение, payload нет
	Enc       string    `json:"enc,omitempty"`
	UpdatedAt string    `json:"updatedAt"`
	Info      valueInfo `json:"info"`
}

type catSecret struct {
	catVersion
	Ref     string       `json:"ref,omitempty"`
	History []catVersion `json:"history,omitempty"`
	Redo    []catVersion `json:"redo,omitempty"`
	Meta    *Meta        `json:"meta,omitempty"`
}

type catalog struct {
	Projects map[string]map[string]catSecret `json:"projects"`
	Extends  map[string][]string             `json:"extends,omitempty"`
}

// errNotSQLite — файл по пути уже не SQLite (стор только что заменили
// обратной миграцией): открытие повторяется с определения формата.
var errNotSQLite = errors.New("файл стора сменил формат во время открытия")

func sqliteDSN(p string, create bool) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		abs = p
	}
	u := url.URL{Scheme: "file", Path: filepath.ToSlash(abs)}
	if !strings.HasPrefix(u.Path, "/") {
		u.Path = "/" + u.Path // C:/… на Windows
	}
	mode := "rw" // без c: открытие не создаёт пустую базу на месте пропавшего файла
	if create {
		mode = "rwc"
	}
	return fmt.Sprintf("%s?mode=%s&_pragma=busy_timeout(%d)&_pragma=synchronous(FULL)&_pragma=journal_size_limit(67108864)",
		u.String(), mode, busyMillis)
}

func openSQL(p string, create bool) (*sqlStore, error) {
	db, err := sql.Open("sqlite", sqliteDSN(p, create))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	conn, err := db.Conn(bg)
	if err != nil {
		db.Close()
		return nil, sqlErr("открытие", err)
	}
	return &sqlStore{db: db, conn: conn}, nil
}

func (d *sqlStore) close() error {
	if d.inTx {
		_, _ = d.conn.ExecContext(bg, "ROLLBACK")
		d.inTx = false
	}
	err := d.conn.Close()
	if cerr := d.db.Close(); err == nil {
		err = cerr
	}
	return err
}

func (d *sqlStore) begin(write bool) error {
	q := "BEGIN"
	if write {
		q = "BEGIN IMMEDIATE"
	}
	if _, err := d.conn.ExecContext(bg, q); err != nil {
		return sqlErr("начало транзакции", err)
	}
	d.inTx = true
	return nil
}

// sqlErr переводит занятость и прочие коды SQLite в понятные ошибки.
func sqlErr(op string, err error) error {
	var se *sqlite.Error
	if errors.As(err, &se) {
		switch se.Code() & 0xff {
		case sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED:
			return fmt.Errorf("хранилище занято другой командой sec дольше %d с (%s)", busyMillis/1000, op)
		case sqlite3.SQLITE_NOTADB:
			return errNotSQLite
		case sqlite3.SQLITE_FULL:
			return fmt.Errorf("нет места на диске (%s): %w", op, err)
		}
	}
	return fmt.Errorf("хранилище (%s): %w", op, err)
}

// readCatalog читает и расшифровывает каталог в открытой транзакции;
// возвращает стор с ленивыми значениями.
func (d *sqlStore) readCatalog(key []byte) (*Store, error) {
	var ver, app int64
	if err := d.conn.QueryRowContext(bg, "PRAGMA user_version").Scan(&ver); err != nil {
		return nil, sqlErr("чтение заголовка", err)
	}
	if err := d.conn.QueryRowContext(bg, "PRAGMA application_id").Scan(&app); err != nil {
		return nil, sqlErr("чтение заголовка", err)
	}
	if app != appID {
		return nil, fmt.Errorf("%s: SQLite-файл, но не хранилище sec", Path())
	}
	if ver > formatV3 {
		return nil, fmt.Errorf("хранилище формата %d, эта сборка sec понимает только ≤ %d — обнови sec", ver, formatV3)
	}
	if err := d.conn.QueryRowContext(bg, "SELECT value FROM sec_meta WHERE name = 'store_id'").Scan(&d.sid); err != nil {
		return nil, sqlErr("чтение store_id", err)
	}
	var blob []byte
	if err := d.conn.QueryRowContext(bg, "SELECT blob FROM sec_catalog WHERE id = 1").Scan(&blob); err != nil {
		return nil, sqlErr("чтение каталога", err)
	}
	pt, err := openBox(key, d.aad("catalog", ""), blob)
	if err != nil {
		return nil, errBadKey
	}
	var cat catalog
	if err := json.Unmarshal(pt, &cat); err != nil {
		return nil, fmt.Errorf("каталог хранилища повреждён: %w", err)
	}
	d.key = key
	st := &Store{Version: storeVersion, Projects: make(map[string]map[string]Secret, len(cat.Projects)), Extends: cat.Extends}
	for p, keys := range cat.Projects {
		if keys == nil {
			st.Projects[p] = nil
			continue
		}
		out := make(map[string]Secret, len(keys))
		for k, s := range keys {
			out[k] = Secret{Val: d.lazy(s.catVersion), Enc: s.Enc, Ref: s.Ref, UpdatedAt: s.UpdatedAt,
				History: d.lazyVersions(s.History), RedoStack: d.lazyVersions(s.Redo), Meta: s.Meta}
		}
		st.Projects[p] = out
	}
	return st, nil
}

func (d *sqlStore) lazy(v catVersion) Value {
	if v.ID == "" {
		return Text("")
	}
	return Value{id: v.ID, info: v.Info, src: d}
}

func (d *sqlStore) lazyVersions(vs []catVersion) []Version {
	if vs == nil {
		return nil
	}
	out := make([]Version, len(vs))
	for i, v := range vs {
		out[i] = Version{d.lazy(v), v.Enc, v.UpdatedAt}
	}
	return out
}

func (d *sqlStore) load(v Value) (string, error) {
	if !d.inTx {
		return "", errors.New("снимок хранилища уже закрыт — значение не прочитано (внутренняя ошибка sec)")
	}
	var blob []byte
	err := d.conn.QueryRowContext(bg, "SELECT blob FROM sec_payload WHERE id = ?", v.id).Scan(&blob)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("значения нет в хранилище (payload %s) — стор повреждён, восстанови из бэкапа", v.id)
	}
	if err != nil {
		return "", sqlErr("чтение значения", err)
	}
	pt, err := openBox(d.key, d.aad("payload", v.id), blob)
	if err != nil {
		return "", fmt.Errorf("payload %s не расшифровался — повреждён или подменён", v.id)
	}
	if len(pt) != v.info.Len || !hmac.Equal(infoOf(string(pt), d.key).Sum, v.info.Sum) {
		return "", fmt.Errorf("payload %s не совпал с каталогом — стор повреждён", v.id)
	}
	return string(pt), nil
}

func (d *sqlStore) aad(role, id string) []byte {
	b := append([]byte(aadPrefix+role+"\x00"), d.sid...)
	if id != "" {
		b = append(append(b, 0), id...)
	}
	return b
}

// create размечает пустую базу: схема, store_id, пустой каталог. Вызывается
// на свежем файле до begin; оставляет открытой транзакцию записи.
func (d *sqlStore) create(key []byte) error {
	for _, q := range []string{
		"PRAGMA auto_vacuum = INCREMENTAL", // до первой таблицы, иначе не применится
		"PRAGMA journal_mode = WAL",
		fmt.Sprintf("PRAGMA application_id = %d", appID),
		fmt.Sprintf("PRAGMA user_version = %d", formatV3),
	} {
		if _, err := d.conn.ExecContext(bg, q); err != nil {
			return sqlErr("создание", err)
		}
	}
	if err := d.begin(true); err != nil {
		return err
	}
	if _, err := d.conn.ExecContext(bg, schemaSQL); err != nil {
		return sqlErr("создание схемы", err)
	}
	d.sid = make([]byte, 16)
	if _, err := rand.Read(d.sid); err != nil {
		return err
	}
	if _, err := d.conn.ExecContext(bg, "INSERT INTO sec_meta(name, value) VALUES ('store_id', ?)", d.sid); err != nil {
		return sqlErr("создание", err)
	}
	d.key = key
	return nil
}

// commit пишет стор в открытую транзакцию записи и коммитит её. Значения,
// уже лежащие payload этого снимка, не перешифровываются (rewrite=false);
// новые получают новые id. Payload, на которые каталог больше не ссылается,
// удаляются в той же транзакции.
func (d *sqlStore) commit(st *Store, key []byte, rewrite bool) error {
	if !d.inTx {
		return errors.New("транзакция записи не открыта (внутренняя ошибка sec)")
	}
	keep := map[string]bool{}
	persist := func(v Value, enc, at string) (catVersion, error) {
		cv := catVersion{Enc: enc, UpdatedAt: at}
		if !rewrite && !v.loaded && v.src == d && v.id != "" {
			cv.ID, cv.Info = v.id, v.info
			keep[v.id] = true
			return cv, nil
		}
		text, err := v.Load()
		if err != nil {
			return cv, err
		}
		if text == "" {
			return cv, nil
		}
		id := make([]byte, 16)
		if _, err := rand.Read(id); err != nil {
			return cv, err
		}
		cv.ID, cv.Info = hex.EncodeToString(id), infoOf(text, key)
		box, err := sealBox(key, d.aad("payload", cv.ID), []byte(text))
		if err != nil {
			return cv, err
		}
		if _, err := d.conn.ExecContext(bg, "INSERT INTO sec_payload(id, blob) VALUES (?, ?)", cv.ID, box); err != nil {
			return cv, sqlErr("запись значения", err)
		}
		keep[cv.ID] = true
		return cv, nil
	}
	versions := func(vs []Version) ([]catVersion, error) {
		if vs == nil {
			return nil, nil
		}
		out := make([]catVersion, len(vs))
		for i, v := range vs {
			cv, err := persist(v.Val, v.Enc, v.UpdatedAt)
			if err != nil {
				return nil, err
			}
			out[i] = cv
		}
		return out, nil
	}

	cat := catalog{Projects: make(map[string]map[string]catSecret, len(st.Projects)), Extends: st.Extends}
	for _, p := range SortedKeys(st.Projects) {
		keys := st.Projects[p]
		if keys == nil {
			cat.Projects[p] = nil
			continue
		}
		out := make(map[string]catSecret, len(keys))
		for _, k := range SortedKeys(keys) {
			s := keys[k]
			cur, err := persist(s.Val, s.Enc, s.UpdatedAt)
			if err != nil {
				return fmt.Errorf("%s/%s: %w", p, k, err)
			}
			hist, err := versions(s.History)
			if err != nil {
				return fmt.Errorf("%s/%s (история): %w", p, k, err)
			}
			redo, err := versions(s.RedoStack)
			if err != nil {
				return fmt.Errorf("%s/%s (redo): %w", p, k, err)
			}
			out[k] = catSecret{catVersion: cur, Ref: s.Ref, History: hist, Redo: redo, Meta: s.Meta}
		}
		cat.Projects[p] = out
	}

	if err := d.gc(keep); err != nil {
		return err
	}
	pt, err := json.Marshal(cat)
	if err != nil {
		return err
	}
	box, err := sealBox(key, d.aad("catalog", ""), pt)
	if err != nil {
		return err
	}
	if _, err := d.conn.ExecContext(bg, "INSERT INTO sec_catalog(id, blob) VALUES (1, ?) ON CONFLICT(id) DO UPDATE SET blob = excluded.blob", box); err != nil {
		return sqlErr("запись каталога", err)
	}
	hook("sqlite:before-commit")
	if _, err := d.conn.ExecContext(bg, "COMMIT"); err != nil {
		return sqlErr("коммит", err)
	}
	d.inTx = false
	d.key = key
	return nil
}

// gc удаляет payload, на которые не ссылается новый каталог, и отдаёт
// освободившееся место файлу, когда его набралось заметно.
func (d *sqlStore) gc(keep map[string]bool) error {
	rows, err := d.conn.QueryContext(bg, "SELECT id FROM sec_payload")
	if err != nil {
		return sqlErr("сборка мусора", err)
	}
	var drop []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return sqlErr("сборка мусора", err)
		}
		if !keep[id] {
			drop = append(drop, id)
		}
	}
	if err := rows.Close(); err != nil {
		return sqlErr("сборка мусора", err)
	}
	if err := rows.Err(); err != nil {
		return sqlErr("сборка мусора", err)
	}
	for _, id := range drop {
		if _, err := d.conn.ExecContext(bg, "DELETE FROM sec_payload WHERE id = ?", id); err != nil {
			return sqlErr("удаление значения", err)
		}
	}
	var free int64
	if err := d.conn.QueryRowContext(bg, "PRAGMA freelist_count").Scan(&free); err != nil {
		return sqlErr("сборка мусора", err)
	}
	if free > 2048 {
		if _, err := d.conn.ExecContext(bg, "PRAGMA incremental_vacuum"); err != nil {
			return sqlErr("сборка мусора", err)
		}
	}
	return nil
}

func sealBox(key, aad, pt []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(pt)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, pt, aad), nil
}

func openBox(key, aad, box []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(box) < aead.NonceSize()+aead.Overhead() {
		return nil, errors.New("короткий блоб")
	}
	n := aead.NonceSize()
	return aead.Open(nil, box[:n], box[n:], aad)
}
