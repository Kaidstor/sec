package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// TokenFile — tokens.json в data-dir: имена и sha256-хэши токенов создателей.
// Файл перечитывается на каждую проверку: `token add` через docker exec виден
// работающему серверу без рестарта.
type TokenFile struct{ path string }

type tokenEntry struct {
	Name      string `json:"name"`
	SHA256    string `json:"sha256"`
	CreatedAt string `json:"createdAt"`
}

type tokensDoc struct {
	V      int          `json:"v"`
	Tokens []tokenEntry `json:"tokens"`
}

func NewTokenFile(dataDir string) *TokenFile {
	return &TokenFile{path: filepath.Join(dataDir, "tokens.json")}
}

func (t *TokenFile) load() (tokensDoc, error) {
	data, err := os.ReadFile(t.path)
	if errors.Is(err, os.ErrNotExist) {
		return tokensDoc{V: 1}, nil
	}
	if err != nil {
		return tokensDoc{}, err
	}
	var doc tokensDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return tokensDoc{}, fmt.Errorf("%s: %w", t.path, err)
	}
	return doc, nil
}

func (t *TokenFile) save(doc tokensDoc) error {
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	tmp := t.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, t.path)
}

// Issue выпускает токен sst_<base64url 32 байта>: значение печатается один
// раз, в файле остаётся только хэш.
func (t *TokenFile) Issue(name string) (string, error) {
	if name == "" || strings.ContainsAny(name, " \t\n") {
		return "", errors.New("имя токена — одно слово без пробелов")
	}
	doc, err := t.load()
	if err != nil {
		return "", err
	}
	for _, e := range doc.Tokens {
		if e.Name == name {
			return "", fmt.Errorf("токен %q уже есть (отозвать: token rm %s)", name, name)
		}
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	token := "sst_" + base64.RawURLEncoding.EncodeToString(raw[:])
	sum := sha256.Sum256([]byte(token))
	doc.V = 1
	doc.Tokens = append(doc.Tokens, tokenEntry{
		Name:      name,
		SHA256:    hex.EncodeToString(sum[:]),
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	})
	if err := t.save(doc); err != nil {
		return "", err
	}
	return token, nil
}

// Verify возвращает имя владельца токена. Сравнение по sha256 в константное
// время; совпадение не прерывает перебор, чтобы время не зависело от позиции.
func (t *TokenFile) Verify(token string) (string, bool) {
	if token == "" {
		return "", false
	}
	doc, err := t.load()
	if err != nil {
		return "", false
	}
	sum := sha256.Sum256([]byte(token))
	got := []byte(hex.EncodeToString(sum[:]))
	name, found := "", false
	for _, e := range doc.Tokens {
		if subtle.ConstantTimeCompare(got, []byte(e.SHA256)) == 1 {
			name, found = e.Name, true
		}
	}
	return name, found
}

func (t *TokenFile) Remove(name string) error {
	doc, err := t.load()
	if err != nil {
		return err
	}
	kept := doc.Tokens[:0]
	found := false
	for _, e := range doc.Tokens {
		if e.Name == name {
			found = true
			continue
		}
		kept = append(kept, e)
	}
	if !found {
		return fmt.Errorf("токена %q нет", name)
	}
	doc.Tokens = kept
	return t.save(doc)
}

func (t *TokenFile) List() ([]tokenEntry, error) {
	doc, err := t.load()
	return doc.Tokens, err
}
