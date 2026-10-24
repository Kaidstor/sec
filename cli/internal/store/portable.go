package store

// Переносимая форма стора — JSON версии storeVersion: тело SECSTOR2, бэкапов
// SECBAK03 и sync-блобов. Полная и самодостаточная: все значения открытым
// текстом внутри зашифрованного контейнера, никаких ссылок на локальные
// payload. Форма полей совпадает с прежним Store, поэтому старые бэкапы
// открываются, а новые открываются старыми бинарями.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// Value — указатель: отсутствие поля и null отличаются от законного "".
// LocalID — только для отказа: id payload бывает лишь в локальном каталоге.
type portableVersion struct {
	Value      *string         `json:"value"`
	Enc        string          `json:"enc,omitempty"`
	UpdatedAt  string          `json:"updatedAt"`
	LocalID    json.RawMessage `json:"id,omitempty"`
	PayloadRef json.RawMessage `json:"payloadRef,omitempty"`
}

type portableSecret struct {
	Value      *string           `json:"value"`
	Enc        string            `json:"enc,omitempty"`
	Ref        string            `json:"ref,omitempty"`
	UpdatedAt  string            `json:"updatedAt"`
	History    []portableVersion `json:"history,omitempty"`
	RedoStack  []portableVersion `json:"redo,omitempty"`
	Meta       *Meta             `json:"meta,omitempty"`
	LocalID    json.RawMessage   `json:"id,omitempty"`
	PayloadRef json.RawMessage   `json:"payloadRef,omitempty"`
}

type portableStore struct {
	Version  int                                  `json:"version"`
	Projects map[string]map[string]portableSecret `json:"projects"`
	Extends  map[string][]string                  `json:"extends,omitempty"`
}

// MarshalPortable — весь стор переносимым JSON. Читает все payload; любой
// недоступный или битый — ошибка, неполного результата не бывает.
func MarshalPortable(st *Store) ([]byte, error) {
	ps, err := toPortable(st)
	if err != nil {
		return nil, err
	}
	return json.Marshal(ps)
}

// ParsePortable разбирает переносимый JSON (бэкап, sync-блоб, тело SECSTOR2).
// Форма, не похожая на стор, — ошибка, а не пустой стор: restore --replace
// по такому блобу снёс бы всё.
func ParsePortable(data []byte) (*Store, error) {
	var ps portableStore
	if err := json.Unmarshal(data, &ps); err != nil {
		return nil, fmt.Errorf("повреждено: %w", err)
	}
	// sec всегда пишет projects объектом ({} у пустого стора); null или
	// отсутствие поля — не наша форма
	if ps.Projects == nil {
		return nil, errors.New("неизвестная форма данных: нет поля projects")
	}
	if ps.Version > storeVersion {
		return nil, fmt.Errorf("схема версии %d, эта сборка sec понимает только ≤ %d — обнови sec (запись старой версией уничтожила бы новые поля)", ps.Version, storeVersion)
	}
	if err := checkPortable(&ps); err != nil {
		return nil, err
	}
	return fromPortable(&ps), nil
}

// checkPortable — у каждой версии (текущей, истории, redo) есть value, и нет
// локальных ссылок на payload. sec всегда пишет value, в том числе "" у
// ссылок; без этой проверки такая запись стала бы пустым секретом.
func checkPortable(ps *portableStore) error {
	bad := func(p, k, part string, value *string, localID, payloadRef json.RawMessage) error {
		if len(localID) > 0 || len(payloadRef) > 0 {
			return fmt.Errorf("%s/%s%s: ссылка на локальный payload — это не переносимая форма", p, k, part)
		}
		if value == nil {
			return fmt.Errorf("%s/%s%s: нет поля value — неизвестная форма данных", p, k, part)
		}
		return nil
	}
	for p, keys := range ps.Projects {
		for k, s := range keys {
			if err := bad(p, k, "", s.Value, s.LocalID, s.PayloadRef); err != nil {
				return err
			}
			for i, v := range s.History {
				if err := bad(p, k, fmt.Sprintf(" (история %d)", i+1), v.Value, v.LocalID, v.PayloadRef); err != nil {
					return err
				}
			}
			for i, v := range s.RedoStack {
				if err := bad(p, k, fmt.Sprintf(" (redo %d)", i+1), v.Value, v.LocalID, v.PayloadRef); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func toPortable(st *Store) (*portableStore, error) {
	ps := &portableStore{Version: storeVersion, Projects: map[string]map[string]portableSecret{}, Extends: st.Extends}
	for p, keys := range st.Projects {
		out := make(map[string]portableSecret, len(keys))
		for k, s := range keys {
			v, err := s.Val.Load()
			if err != nil {
				return nil, fmt.Errorf("%s/%s: %w", p, k, err)
			}
			hist, err := portableVersions(s.History)
			if err != nil {
				return nil, fmt.Errorf("%s/%s (история): %w", p, k, err)
			}
			redo, err := portableVersions(s.RedoStack)
			if err != nil {
				return nil, fmt.Errorf("%s/%s (redo): %w", p, k, err)
			}
			out[k] = portableSecret{Value: &v, Enc: s.Enc, Ref: s.Ref, UpdatedAt: s.UpdatedAt, History: hist, RedoStack: redo, Meta: s.Meta}
		}
		ps.Projects[p] = out
	}
	return ps, nil
}

func portableVersions(vs []Version) ([]portableVersion, error) {
	if vs == nil {
		return nil, nil
	}
	out := make([]portableVersion, len(vs))
	for i, v := range vs {
		t, err := v.Val.Load()
		if err != nil {
			return nil, err
		}
		out[i] = portableVersion{Value: &t, Enc: v.Enc, UpdatedAt: v.UpdatedAt}
	}
	return out, nil
}

func fromPortable(ps *portableStore) *Store {
	st := &Store{Version: ps.Version, Projects: make(map[string]map[string]Secret, len(ps.Projects)), Extends: ps.Extends}
	for p, keys := range ps.Projects {
		if keys == nil {
			st.Projects[p] = nil
			continue
		}
		out := make(map[string]Secret, len(keys))
		for k, s := range keys {
			out[k] = Secret{Val: Text(deref(s.Value)), Enc: s.Enc, Ref: s.Ref, UpdatedAt: s.UpdatedAt,
				History: fromPortableVersions(s.History), RedoStack: fromPortableVersions(s.RedoStack), Meta: s.Meta}
		}
		st.Projects[p] = out
	}
	return st
}

func fromPortableVersions(vs []portableVersion) []Version {
	if vs == nil {
		return nil
	}
	out := make([]Version, len(vs))
	for i, v := range vs {
		out[i] = Version{Text(deref(v.Value)), v.Enc, v.UpdatedAt}
	}
	return out
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// samePortable — совпадают ли две логические модели байт-в-байт в
// каноническом JSON (encoding/json сортирует ключи карт).
func samePortable(a, b *Store) (bool, error) {
	ja, err := MarshalPortable(a)
	if err != nil {
		return false, err
	}
	jb, err := MarshalPortable(b)
	if err != nil {
		return false, err
	}
	return bytes.Equal(ja, jb), nil
}
