package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// SecretRecord — один секрет на диске: непрозрачный шифроблоб плюс метаданные
// жизни ссылки. Расшифровать его сервер не может — ключ существует только в
// URL-фрагменте у создателя и получателя.
type SecretRecord struct {
	V         int       `json:"v"`
	ID        string    `json:"id"`
	Blob      []byte    `json:"blob"`
	Once      bool      `json:"once"`
	TokenName string    `json:"tokenName"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	Claims    int       `json:"claims"`
}

type Storage struct {
	dir string
	mu  sync.Mutex
	now func() time.Time
}

func NewStorage(dir string) (*Storage, error) {
	for _, sub := range []string{"secrets", "claimed"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			return nil, err
		}
	}
	return &Storage{dir: dir, now: func() time.Time { return time.Now().UTC() }}, nil
}

// path: имя файла — sha256(id), а не сам id: листинг каталога не является
// списком действующих URL, а path traversal исключён на уровне имени.
func (s *Storage) path(id string) string {
	sum := sha256.Sum256([]byte(id))
	return filepath.Join(s.dir, "secrets", hex.EncodeToString(sum[:])+".json")
}

func writeFileAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *Storage) Save(rec SecretRecord) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return writeFileAtomic(s.path(rec.ID), data)
}

func readRecord(path string) (SecretRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return SecretRecord{}, err
	}
	var rec SecretRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return SecretRecord{}, err
	}
	return rec, nil
}

// Claim выдаёт секрет получателю. Для once атомарный клейм — os.Rename в
// claimed/: первый победил, проигравший (в том числе второй контейнер над тем
// же volume в момент деплоя) получает ENOENT. Если ответ получателю не
// дописался — секрет всё равно сгорел, не реанимируем.
func (s *Storage) Claim(id string) (SecretRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	path := s.path(id)
	rec, err := readRecord(path)
	if err != nil {
		return SecretRecord{}, false
	}
	if !rec.ExpiresAt.After(s.now()) {
		_ = os.Remove(path)
		return SecretRecord{}, false
	}
	rec.Claims++
	if rec.Once {
		claimed := filepath.Join(s.dir, "claimed",
			fmt.Sprintf("%s.%d", filepath.Base(path), s.now().UnixNano()))
		if err := os.Rename(path, claimed); err != nil {
			return SecretRecord{}, false
		}
		// падение между rename и Remove доберёт reaper по возрасту файла
		_ = os.Remove(claimed)
		return rec, true
	}
	if data, err := json.Marshal(rec); err == nil {
		_ = writeFileAtomic(path, data) // счётчик информационный, гонка некритична
	}
	return rec, true
}

// List — активные записи одного создателя, без блобов, старые первыми.
func (s *Storage) List(tokenName string) ([]SecretRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(filepath.Join(s.dir, "secrets"))
	if err != nil {
		return nil, err
	}
	now := s.now()
	var out []SecretRecord
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		rec, err := readRecord(filepath.Join(s.dir, "secrets", e.Name()))
		if err != nil || rec.TokenName != tokenName || !rec.ExpiresAt.After(now) {
			continue
		}
		rec.Blob = nil
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

// Delete — отзыв создателем: чужая запись неотличима от несуществующей.
func (s *Storage) Delete(id, tokenName string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	path := s.path(id)
	rec, err := readRecord(path)
	if err != nil || rec.TokenName != tokenName {
		return false
	}
	return os.Remove(path) == nil
}

// Reap удаляет протухшие и нечитаемые записи, осиротевшие *.tmp и зависшие
// файлы клейма (обычно claimed/ пуст — Claim подчищает за собой сразу).
func (s *Storage) Reap() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	secrets := filepath.Join(s.dir, "secrets")
	if entries, err := os.ReadDir(secrets); err == nil {
		for _, e := range entries {
			path := filepath.Join(secrets, e.Name())
			if strings.HasSuffix(e.Name(), ".tmp") {
				if fi, err := e.Info(); err == nil && now.Sub(fi.ModTime().UTC()) > time.Hour {
					_ = os.Remove(path)
				}
				continue
			}
			if rec, err := readRecord(path); err != nil || !rec.ExpiresAt.After(now) {
				_ = os.Remove(path)
			}
		}
	}
	claimed := filepath.Join(s.dir, "claimed")
	if entries, err := os.ReadDir(claimed); err == nil {
		for _, e := range entries {
			if fi, err := e.Info(); err == nil && now.Sub(fi.ModTime().UTC()) > time.Hour {
				_ = os.Remove(filepath.Join(claimed, e.Name()))
			}
		}
	}
}

func (s *Storage) StartReaper(every time.Duration, stop <-chan struct{}) {
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				s.Reap()
			case <-stop:
				return
			}
		}
	}()
}
