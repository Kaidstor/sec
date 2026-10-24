package store

// Доменная модель стора: проекты, ключи, версии, ссылки и наследование.
// Хранение — session.go (снимки и транзакции записи), форматы на диске —
// sqlite.go (SECSTOR3, локальная SQLite с шифрованием в приложении) и
// legacy.go (SECSTOR2, один зашифрованный JSON). Переносимая форма для
// backup/sync — portable.go.

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// storeVersion — версия переносимой схемы (JSON внутри SECSTOR2 и бэкапов).
// Открытие отказывается от более новой: бинарь, не знающий свежих полей
// (например enc у бинарных секретов), молча уничтожил бы их при записи.
// Версия 2 — появилось поле Secret.Enc (бинарные файловые секреты).
const storeVersion = 2

// maxHistory — сколько предыдущих значений ключа хранить (для get --prev / undo).
const maxHistory = 5

// EncB64 — маркер бинарного значения: значение — base64 сырых байт
// (файловые секреты — сертификаты, ключи, keystore). Пустой Enc — обычный текст.
const EncB64 = "b64"

// KindConfig — значение Meta.Kind для несекретных настроек (см. Secret.IsConfig).
const KindConfig = "config"

type Version struct {
	Val       Value
	Enc       string
	UpdatedAt string
}

// Meta — несекретные метаданные ключа: описание, назначение, политика ротации.
// Живут отдельно от значения и переживают перезапись значения (set/gen/undo).
type Meta struct {
	Note        string `json:"note,omitempty"`
	Kind        string `json:"kind,omitempty"`        // password | apikey | totp | file | env | ...
	Filename    string `json:"filename,omitempty"`    // имя исходного файла (set --from-file)
	FileMode    string `json:"fileMode,omitempty"`    // исходные права файла восьмерично ("0644"); версию стора не бампаем — потеря поля старым бинарём безвредна (get --out откатится к 0600)
	RotateURL   string `json:"rotateUrl,omitempty"`   // где крутить секрет
	RotateEvery string `json:"rotateEvery,omitempty"` // человекочитаемый интервал, напр. "90d"
	ExpiresAt   string `json:"expiresAt,omitempty"`   // RFC3339, дедлайн ротации
}

type Secret struct {
	Val       Value
	Enc       string    // "" — текст; EncB64 — бинарные байты в base64
	Ref       string    // внутренний "proj/KEY" — живая ссылка на чужое значение; своего значения нет
	UpdatedAt string    //
	History   []Version // прошлые значения, новейшее первым (для undo / get --prev)
	RedoStack []Version // отменённые через undo значения, ближайшее первым (для redo)
	Meta      *Meta     // несекретные метаданные (nil, если не заданы)
}

// IsBinary — значение бинарное (файловый секрет): в env/шаблон/буфер его не
// отдать, доставать только файлом (get --out).
func (s Secret) IsBinary() bool { return s.Enc == EncB64 }

// IsFile — файловый секрет: бинарное значение либо kind=file в метаданных
// (текстовые PEM/сертификаты). В env-инъекцию run/export по умолчанию не
// попадает — потреблять через run --file / get --out.
func (s Secret) IsFile() bool {
	return s.Enc == EncB64 || (s.Meta != nil && s.Meta.Kind == "file")
}

// IsConfig — значение не секрет, а настройка (kind: config): endpoint, размер
// кэша, список провайдеров. Такие scan/redact не считают утечкой, а diff/deploy
// показывают открытым текстом — отпечатка мало, чтобы понять «что там сейчас».
func (s Secret) IsConfig() bool { return s.Meta != nil && s.Meta.Kind == KindConfig }

// Bytes — сырые байты текущего значения: для бинарных — декодированный
// base64, для текста — байты строки как есть.
func (s Secret) Bytes() ([]byte, error) { return Version{s.Val, s.Enc, s.UpdatedAt}.Bytes() }

// Bytes — сырые байты значения версии (см. Secret.Bytes).
func (v Version) Bytes() ([]byte, error) {
	text, err := v.Val.Load()
	if err != nil {
		return nil, err
	}
	if v.Enc == EncB64 {
		b, err := base64.StdEncoding.DecodeString(text)
		if err != nil {
			return nil, fmt.Errorf("битый base64 бинарного значения: %w", err)
		}
		return b, nil
	}
	return []byte(text), nil
}

// Loaded — копия секрета с расшифрованным текущим значением: она переживает
// Close снимка (run/deploy/share закрывают стор до дочерних процессов и сети).
func (s Secret) Loaded() (Secret, error) {
	text, err := s.Val.Load()
	if err != nil {
		return s, err
	}
	s.Val = Text(text)
	return s, nil
}

type Store struct {
	Version  int
	Projects map[string]map[string]Secret
	Extends  map[string][]string // proj → родительские пачки: их ключи видны в proj read-only

	sess *session // nil — стор собран в памяти (тесты, бэкап)
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
	if base == "" && runtime.GOOS == "windows" {
		base = os.Getenv("LOCALAPPDATA") // конвенция Windows: данные — в local AppData
	}
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(base, "sec", "store.enc")
}

// Put записывает текстовое значение ключа, утаскивая прежнее значение в
// историю (если оно реально поменялось). Возвращает, существовал ли ключ.
func Put(m map[string]Secret, key, val string) bool { return PutEnc(m, key, val, "") }

// PutEnc — Put с явной кодировкой значения ("" — текст, EncB64 — бинарь).
func PutEnc(m map[string]Secret, key, val, enc string) bool {
	return putValue(m, key, Text(val), enc)
}

func putValue(m map[string]Secret, key string, val Value, enc string) bool {
	old, existed := m[key]
	sec := Secret{Val: val, Enc: enc, UpdatedAt: Now()}
	if existed {
		sec.Meta = old.Meta // метаданные описывают ключ, а не значение — переносим
		if old.Val.equal(val) && old.Enc == enc {
			// значение не изменилось — это no-op, сохраняем историю и redo как есть.
			sec.Val = old.Val
			sec.History = old.History
			sec.RedoStack = old.RedoStack
		} else {
			sec.History = append([]Version{{old.Val, old.Enc, old.UpdatedAt}}, old.History...)
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
		Val:       prev.Val,
		Enc:       prev.Enc,
		UpdatedAt: prev.UpdatedAt, // таймстемп версии сохраняем честным, не Now()
		History:   append([]Version(nil), s.History[1:]...),
		RedoStack: append([]Version{{s.Val, s.Enc, s.UpdatedAt}}, s.RedoStack...),
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
	hist := append([]Version{{s.Val, s.Enc, s.UpdatedAt}}, s.History...)
	if len(hist) > maxHistory {
		hist = hist[:maxHistory]
	}
	return Secret{
		Val:       fwd.Val,
		Enc:       fwd.Enc,
		UpdatedAt: fwd.UpdatedAt,
		History:   hist,
		RedoStack: append([]Version(nil), s.RedoStack[1:]...),
		Meta:      s.Meta,
	}, true
}

// forget возвращает секрет без истории и redo (текущее значение и мета остаются).
func (s Secret) Forget() Secret {
	return Secret{Val: s.Val, Enc: s.Enc, UpdatedAt: s.UpdatedAt, Meta: s.Meta}
}

// Merge вливает src в dst: значения из src побеждают, вытесненные
// локальные уходят в историю (ничего не теряется). Метаданные подтягиваются из
// src, если у dst их не было. Ключ, которого в dst нет, переносится целиком —
// с историей, redo и ссылкой. Входящая ссылка поверх локального собственного
// значения не применяется (у ссылки нет истории, локальное значение пропало
// бы) — такие адреса возвращаются в skipped.
func Merge(dst, src *Store) (added, updated int, skipped []string) {
	for _, p := range SortedKeys(src.Projects) {
		keys := src.Projects[p]
		dp := dst.Project(p)
		for _, k := range SortedKeys(keys) {
			s := keys[k]
			cur, exists := dp[k]
			if !exists {
				dp[k] = s
				added++
				continue
			}
			if s.Ref != "" || cur.Ref != "" {
				switch {
				case s.Ref == cur.Ref:
				case s.Ref != "" && cur.Ref == "":
					skipped = append(skipped, p+"/"+k)
				default: // у локальной ссылки своего значения нет — терять нечего
					dp[k] = s
					updated++
				}
				continue
			}
			if cur.Val.equal(s.Val) && cur.Enc == s.Enc {
				if cur.Meta == nil && s.Meta != nil {
					cur.Meta = s.Meta
					dp[k] = cur
				}
				continue
			}
			putValue(dp, k, s.Val, s.Enc)
			updated++
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
	return added, updated, skipped
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

// SplitRef — экспортированная форма splitRef для CLI-слоя: разобрать
// внутренний адрес "proj/KEY" на проект и ключ.
func SplitRef(ref string) (proj, key string, ok bool) { return splitRef(ref) }

// splitRef разбирает внутренний адрес "proj/KEY" (proj может быть
// service@profile, оба конца без '/'). Внутренний адрес совпадает с
// CLI-формой — в подсказки и сообщения он идёт как есть.
func splitRef(ref string) (proj, key string, ok bool) {
	i := strings.LastIndexByte(ref, '/')
	if i <= 0 || i == len(ref)-1 {
		return "", "", false
	}
	return ref[:i], ref[i+1:], true
}

// DisplayProj — внутреннее имя проекта как копипастный CLI-адрес. Базовый
// набор сервиса, у которого в сторе есть профили, печатается явной формой
// "svc@": голый "svc", вставленный в папке с default из .sec, разрешился бы
// в дефолтный профиль — то есть в другой набор секретов.
func (st *Store) DisplayProj(proj string) string {
	base, prof := BaseAndProfile(proj)
	if prof != "" {
		return proj
	}
	for p := range st.Projects {
		if b, pr := BaseAndProfile(p); b == base && pr != "" {
			return proj + "@"
		}
	}
	return proj
}

// DisplayRef — DisplayProj для полного адреса "proj/KEY".
func (st *Store) DisplayRef(ref string) string {
	proj, key, ok := splitRef(ref)
	if !ok {
		return ref
	}
	return st.DisplayProj(proj) + "/" + key
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

// referrers возвращает адреса ключей-ссылок, чей Ref указывает ровно на
// target ("proj/KEY"). Для предупреждения перед удалением ключа: такие ссылки
// станут битыми.
func (st *Store) Referrers(target string) []string {
	var out []string
	for _, p := range SortedKeys(st.Projects) {
		for _, k := range SortedKeys(st.Projects[p]) {
			if st.Projects[p][k].Ref == target {
				out = append(out, st.DisplayRef(p+"/"+k))
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
				out = append(out, st.DisplayRef(p+"/"+k))
			}
		}
	}
	return out
}

// extenders — имена проектов, напрямую наследующих от parent.
func (st *Store) Extenders(parent string) []string {
	var out []string
	for _, p := range SortedKeys(st.Extends) {
		for _, pp := range st.Extends[p] {
			if pp == parent {
				out = append(out, st.DisplayProj(p))
				break
			}
		}
	}
	return out
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
