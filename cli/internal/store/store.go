package store

// Хранилище: один файл, целиком зашифрованный XChaCha20-Poly1305. Мастер-ключ
// отдельно (keyring.go). Значения секретов никогда не пишутся на диск
// открытым текстом и не попадают в argv. Запись атомарная (tmp + rename)
// под файловой блокировкой.

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/kaidstor/sec/internal/keyring"
)

const storeMagic = "SECSTOR2"

// maxHistory — сколько предыдущих значений ключа хранить (для get --prev / undo).
const maxHistory = 5

type Version struct {
	Value     string `json:"value"`
	UpdatedAt string `json:"updatedAt"`
}

// Meta — несекретные метаданные ключа: описание, назначение, политика ротации.
// Живут отдельно от значения и переживают перезапись значения (set/gen/undo).
type Meta struct {
	Note        string `json:"note,omitempty"`
	Kind        string `json:"kind,omitempty"`        // password | apikey | totp | env | ...
	RotateURL   string `json:"rotateUrl,omitempty"`   // где крутить секрет
	RotateEvery string `json:"rotateEvery,omitempty"` // человекочитаемый интервал, напр. "90d"
	ExpiresAt   string `json:"expiresAt,omitempty"`   // RFC3339, дедлайн ротации
}

type Secret struct {
	Value     string    `json:"value"`
	Ref       string    `json:"ref,omitempty"` // внутренний "proj/KEY" — живая ссылка на чужое значение; своего Value нет
	UpdatedAt string    `json:"updatedAt"`
	History   []Version `json:"history,omitempty"` // прошлые значения, новейшее первым (для undo / get --prev)
	RedoStack []Version `json:"redo,omitempty"`    // отменённые через undo значения, ближайшее первым (для redo)
	Meta      *Meta     `json:"meta,omitempty"`    // несекретные метаданные (nil, если не заданы)
}

type Store struct {
	Version  int                          `json:"version"`
	Projects map[string]map[string]Secret `json:"projects"`
	Extends  map[string][]string          `json:"extends,omitempty"` // proj → родительские пачки: их ключи видны в proj read-only
}

// project возвращает карту ключей проекта, создавая её при отсутствии.
func (st *Store) Project(proj string) map[string]Secret {
	if st.Projects[proj] == nil {
		st.Projects[proj] = map[string]Secret{}
	}
	return st.Projects[proj]
}

// prune удаляет проект, если в нём не осталось ключей.
func (st *Store) Prune(proj string) {
	if len(st.Projects[proj]) == 0 {
		delete(st.Projects, proj)
	}
}

func Path() string {
	if p := os.Getenv("SEC_STORE"); p != "" {
		return p
	}
	base := os.Getenv("XDG_DATA_HOME")
	if base == "" {
		base = filepath.Join(os.Getenv("HOME"), ".local", "share")
	}
	return filepath.Join(base, "sec", "store.enc")
}

// Put записывает значение ключа, утаскивая прежнее значение в историю
// (если оно реально поменялось). Возвращает, существовал ли ключ.
func Put(m map[string]Secret, key, val string) bool {
	old, existed := m[key]
	sec := Secret{Value: val, UpdatedAt: Now()}
	if existed {
		sec.Meta = old.Meta // метаданные описывают ключ, а не значение — переносим
		if old.Value == val {
			// значение не изменилось — это no-op, сохраняем историю и redo как есть.
			sec.History = old.History
			sec.RedoStack = old.RedoStack
		} else {
			sec.History = append([]Version{{old.Value, old.UpdatedAt}}, old.History...)
			if len(sec.History) > maxHistory {
				sec.History = sec.History[:maxHistory]
			}
			// новое значение делает «будущее» недостижимым — обнуляем redo
			// (семантика редактора: правка после отмены стирает redo-стек).
			sec.RedoStack = nil
		}
	}
	m[key] = sec
	return existed
}

// undo снимает самое свежее прошлое значение (History[0]) в текущее, а
// вытесненное текущее кладёт в стек redo. Второй результат — удалось ли
// (false, если истории больше нет). Чистая функция: тестируется без диска.
func (s Secret) Undo() (Secret, bool) {
	if len(s.History) == 0 {
		return s, false
	}
	prev := s.History[0]
	return Secret{
		Value:     prev.Value,
		UpdatedAt: prev.UpdatedAt, // таймстемп версии сохраняем честным, не Now()
		History:   append([]Version(nil), s.History[1:]...),
		RedoStack: append([]Version{{s.Value, s.UpdatedAt}}, s.RedoStack...),
		Meta:      s.Meta,
	}, true
}

// redo — обратная к undo: возвращает ближайшее отменённое значение (Redo[0])
// в текущее, вытесненное текущее уходит обратно в историю.
func (s Secret) Redo() (Secret, bool) {
	if len(s.RedoStack) == 0 {
		return s, false
	}
	fwd := s.RedoStack[0]
	hist := append([]Version{{s.Value, s.UpdatedAt}}, s.History...)
	if len(hist) > maxHistory {
		hist = hist[:maxHistory]
	}
	return Secret{
		Value:     fwd.Value,
		UpdatedAt: fwd.UpdatedAt,
		History:   hist,
		RedoStack: append([]Version(nil), s.RedoStack[1:]...),
		Meta:      s.Meta,
	}, true
}

// forget возвращает секрет без истории и redo (текущее значение и мета остаются).
func (s Secret) Forget() Secret {
	return Secret{Value: s.Value, UpdatedAt: s.UpdatedAt, Meta: s.Meta}
}

// Merge вливает src в dst: значения из src побеждают, вытесненные
// локальные уходят в историю (ничего не теряется). Метаданные подтягиваются из
// src, если у dst их не было. Возвращает счётчики добавленных/обновлённых.
func Merge(dst, src *Store) (added, updated int) {
	for p, keys := range src.Projects {
		dp := dst.Project(p)
		for k, s := range keys {
			cur, exists := dp[k]
			if exists && cur.Value == s.Value {
				if cur.Meta == nil && s.Meta != nil {
					cur.Meta = s.Meta
					dp[k] = cur
				}
				continue
			}
			if Put(dp, k, s.Value) {
				updated++
			} else {
				added++
			}
			if s.Meta != nil {
				e := dp[k]
				if e.Meta == nil {
					e.Meta = s.Meta
					dp[k] = e
				}
			}
		}
	}
	// наследование пачек — тоже часть стора: подтягиваем связи из src (без дублей/циклов)
	for p, parents := range src.Extends {
		for _, parent := range parents {
			dst.AddExtend(p, parent)
		}
	}
	return added, updated
}

// ---------------------------------------------------------------------------
// Ссылки (link) и наследование пачек (extend): один резолвер на всё чтение,
// один гейт на всю запись.
//
//	Ссылка   — Secret.Ref: ключ проекта указывает на чужой "proj/KEY", своего
//	           значения не хранит; при чтении отдаётся значение родителя.
//	Наследование — Store.Extends[proj]: проект видит все ключи родительских
//	           пачек read-only; собственные ключи перекрывают унаследованные.
// ---------------------------------------------------------------------------

// Origin — откуда в итоге взялось значение ключа.
type Origin int

const (
	OriginOwn    Origin = iota // собственное значение проекта
	OriginRef                  // по ссылке (link) на другой ключ
	OriginExtend               // унаследовано из родительской пачки (extend)
)

const maxRefDepth = 32 // предел длины цепочки ссылок (заодно защита от циклов)

// splitRef разбирает внутренний адрес "proj/KEY" (proj может быть service@env,
// оба конца без '/').
func splitRef(ref string) (proj, key string, ok bool) {
	i := strings.LastIndexByte(ref, '/')
	if i <= 0 || i == len(ref)-1 {
		return "", "", false
	}
	return ref[:i], ref[i+1:], true
}

// RefToCLI переводит внутренний адрес "service@env/KEY" в удобную для набора
// форму "service/KEY" или "service/KEY -e env" (для подсказок в сообщениях).
func RefToCLI(internal string) string {
	proj, key, ok := splitRef(internal)
	if !ok {
		return internal
	}
	svc, env := BaseAndEnv(proj)
	if env == "" {
		return svc + "/" + key
	}
	return svc + "/" + key + " -e " + env
}

// RefToCLIProj переводит внутренний проект "service@env" в CLI-форму
// "service" или "service -e env".
func RefToCLIProj(proj string) string {
	svc, env := BaseAndEnv(proj)
	if env == "" {
		return svc
	}
	return svc + " -e " + env
}

// resolveSecret идёт по цепочке ссылок от собственного ключа proj/key к
// настоящему значению (наследование Extends здесь не учитывается). source —
// внутренний адрес источника ("" если ключ собственный без ссылки). ok=false,
// если ключа нет, ссылка битая или цепочка зациклилась.
func (st *Store) ResolveSecret(proj, key string) (sec Secret, source string, ok bool) {
	for depth := 0; depth < maxRefDepth; depth++ {
		s, has := st.Projects[proj][key]
		if !has {
			return Secret{}, source, false
		}
		if s.Ref == "" {
			return s, source, true
		}
		p, k, good := splitRef(s.Ref)
		if !good {
			return Secret{}, s.Ref, false
		}
		proj, key, source = p, k, s.Ref
	}
	return Secret{}, source, false // слишком длинно — считаем циклом
}

// lookup находит эффективное значение ключа: собственный (с разрешением
// ссылки), иначе — унаследованный из родительских пачек (вглубь). source —
// внутренний адрес настоящего значения для ref/extend (для сообщений).
func (st *Store) Lookup(proj, key string) (sec Secret, org Origin, source string, ok bool) {
	if own, has := st.Projects[proj][key]; has {
		if own.Ref == "" {
			return own, OriginOwn, "", true
		}
		if r, src, good := st.ResolveSecret(proj, key); good {
			return r, OriginRef, src, true
		}
		return Secret{}, OriginRef, own.Ref, false // ссылка есть, но битая
	}
	seen := map[string]bool{}
	var walk func(p string) (Secret, string, bool)
	walk = func(p string) (Secret, string, bool) {
		if seen[p] {
			return Secret{}, "", false
		}
		seen[p] = true
		for _, parent := range st.Extends[p] {
			if r, src, good := st.ResolveSecret(parent, key); good {
				if src == "" {
					src = parent + "/" + key
				}
				return r, src, true
			}
			if r, src, good := walk(parent); good {
				return r, src, true
			}
		}
		return Secret{}, "", false
	}
	if r, src, good := walk(proj); good {
		return r, OriginExtend, src, true
	}
	return Secret{}, OriginOwn, "", false
}

// effectiveKeys собирает эффективный набор ключей проекта: унаследованные из
// родительских пачек под собственными, собственные перекрывают; ссылки
// разрешены в настоящие значения. Битые ссылки пропускаются.
func (st *Store) EffectiveKeys(proj string) map[string]Secret {
	out := map[string]Secret{}
	st.collectKeys(proj, out, map[string]bool{})
	return out
}

func (st *Store) collectKeys(proj string, out map[string]Secret, seen map[string]bool) {
	if seen[proj] {
		return
	}
	seen[proj] = true
	// родители в обратном порядке: более ранний в списке важнее (перекрывает поздних)
	parents := st.Extends[proj]
	for i := len(parents) - 1; i >= 0; i-- {
		st.collectKeys(parents[i], out, seen)
	}
	for k := range st.Projects[proj] {
		if sec, _, ok := st.ResolveSecret(proj, k); ok {
			out[k] = sec
		}
	}
}

// extendReaches — достижим ли target из from по цепочке Extends (для отлова
// циклов наследования до их создания).
func (st *Store) extendReaches(from, target string, seen map[string]bool) bool {
	if from == target {
		return true
	}
	if seen[from] {
		return false
	}
	seen[from] = true
	for _, p := range st.Extends[from] {
		if st.extendReaches(p, target, seen) {
			return true
		}
	}
	return false
}

// addExtend добавляет parent в родители proj без дублей; false — если это создало
// бы цикл (тогда не добавляет).
func (st *Store) AddExtend(proj, parent string) bool {
	if proj == parent || st.extendReaches(parent, proj, map[string]bool{}) {
		return false
	}
	for _, p := range st.Extends[proj] {
		if p == parent {
			return true // уже есть — идемпотентно
		}
	}
	if st.Extends == nil {
		st.Extends = map[string][]string{}
	}
	st.Extends[proj] = append(st.Extends[proj], parent)
	return true
}

// removeExtend убирает parent из родителей proj; false — если такой связи не было.
func (st *Store) RemoveExtend(proj, parent string) bool {
	cur := st.Extends[proj]
	out := cur[:0:0]
	found := false
	for _, p := range cur {
		if p == parent {
			found = true
			continue
		}
		out = append(out, p)
	}
	if !found {
		return false
	}
	if len(out) == 0 {
		delete(st.Extends, proj)
	} else {
		st.Extends[proj] = out
	}
	return found
}

// referrers возвращает CLI-адреса ключей-ссылок, чей Ref указывает ровно на
// target ("proj/KEY"). Для предупреждения перед удалением ключа: такие ссылки
// станут битыми.
func (st *Store) Referrers(target string) []string {
	var out []string
	for _, p := range SortedKeys(st.Projects) {
		for _, k := range SortedKeys(st.Projects[p]) {
			if st.Projects[p][k].Ref == target {
				out = append(out, RefToCLI(p+"/"+k))
			}
		}
	}
	return out
}

// projectReferrers — CLI-адреса ключей-ссылок, указывающих на любой ключ
// проекта proj (для предупреждения перед удалением проекта целиком).
func (st *Store) ProjectReferrers(proj string) []string {
	var out []string
	for _, p := range SortedKeys(st.Projects) {
		for _, k := range SortedKeys(st.Projects[p]) {
			s := st.Projects[p][k]
			if s.Ref == "" {
				continue
			}
			if rp, _, ok := splitRef(s.Ref); ok && rp == proj {
				out = append(out, RefToCLI(p+"/"+k))
			}
		}
	}
	return out
}

// extenders — CLI-имена проектов, напрямую наследующих от parent.
func (st *Store) Extenders(parent string) []string {
	var out []string
	for _, p := range SortedKeys(st.Extends) {
		for _, pp := range st.Extends[p] {
			if pp == parent {
				out = append(out, RefToCLIProj(p))
				break
			}
		}
	}
	return out
}

// Open загружает и расшифровывает хранилище. create=true разрешает
// инициализацию (генерацию мастер-ключа и пустого стора) при первом запуске.
func Open(create bool) (*Store, []byte, string, error) {
	key, backend, err := keyring.Load(create)
	if err != nil {
		return nil, nil, "", err
	}
	st := &Store{Version: 1, Projects: map[string]map[string]Secret{}}
	data, err := os.ReadFile(Path())
	if errors.Is(err, os.ErrNotExist) {
		return st, key, backend, nil
	}
	if err != nil {
		return nil, nil, "", err
	}
	pt, err := decrypt(key, data)
	if err != nil {
		return nil, nil, "", err
	}
	if err := json.Unmarshal(pt, st); err != nil {
		return nil, nil, "", fmt.Errorf("хранилище повреждено: %w", err)
	}
	if st.Projects == nil {
		st.Projects = map[string]map[string]Secret{}
	}
	return st, key, backend, nil
}

// Lock берёт эксклюзивную файловую блокировку на время мутации хранилища
// (защита от параллельных записей read-modify-write). Best-effort: если lock
// недоступен, работаем без него.
func Lock() func() {
	p := Path() + ".lock"
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return func() {}
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return func() {}
	}
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}
}

func Save(st *Store, key []byte) error {
	pt, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	ct, err := encrypt(key, pt)
	if err != nil {
		return err
	}
	p := Path()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, ct, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

func encrypt(key, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append([]byte(storeMagic), nonce...)
	return aead.Seal(out, nonce, plaintext, []byte(storeMagic)), nil
}

func decrypt(key, data []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	head := len(storeMagic) + aead.NonceSize()
	if len(data) < head || string(data[:len(storeMagic)]) != storeMagic {
		return nil, fmt.Errorf("%s: не похоже на хранилище sec", Path())
	}
	nonce := data[len(storeMagic):head]
	pt, err := aead.Open(nil, nonce, data[head:], []byte(storeMagic))
	if err != nil {
		return nil, errors.New("не удалось расшифровать хранилище: неверный мастер-ключ или файл повреждён")
	}
	return pt, nil
}

// ---------------------------------------------------------------------------
// Мелкие утилиты представления
// ---------------------------------------------------------------------------

// MaskValue — безопасное отображение значения: первые/последние 2 символа.
func MaskValue(v string) string {
	r := []rune(v)
	if len(r) < 8 {
		return "····"
	}
	return string(r[:2]) + "…" + string(r[len(r)-2:])
}

func Now() string { return time.Now().Format(time.RFC3339) }

func SortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
