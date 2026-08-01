// Пакет share — одноразовые ссылки: формат шифроблоба и клиент сервера
// sec-share. Zero-knowledge: блоб шифруется здесь случайным ключом, ключ едет
// только в URL-фрагменте (сервер его не видит), расшифровка — у получателя.
package share

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Формат блоба: "secshare" + байт версии + nonce(12) + AES-256-GCM (тег в
// хвосте), AAD — первые 9 байт. AES-GCM вместо XChaCha20 стора — единственный
// AEAD, который умеет WebCrypto: страница раскрытия расшифровывает в браузере.
const (
	Magic     = "secshare"
	Version   = 1
	KeyLen    = 32
	headerLen = len(Magic) + 1
	nonceLen  = 12
)

// Envelope — то, что видит получатель после расшифровки. Имя и права файла
// едут внутри шифротекста: сервер не видит даже их.
type Envelope struct {
	V        int    `json:"v"`
	Type     string `json:"type"` // "text" | "file"
	Filename string `json:"filename,omitempty"`
	Mode     string `json:"mode,omitempty"`
	Data     []byte `json:"data"`
}

func NewKey() ([]byte, error) {
	key := make([]byte, KeyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

func Encode(key []byte, env Envelope) ([]byte, error) {
	if len(key) != KeyLen {
		return nil, fmt.Errorf("ключ должен быть %d байт", KeyLen)
	}
	env.V = Version
	plain, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	blob := make([]byte, 0, headerLen+nonceLen+len(plain)+gcm.Overhead())
	blob = append(blob, Magic...)
	blob = append(blob, Version)
	blob = append(blob, nonce...)
	return gcm.Seal(blob, nonce, plain, blob[:headerLen]), nil
}

func Decode(key, blob []byte) (Envelope, error) {
	if len(key) != KeyLen {
		return Envelope{}, fmt.Errorf("ключ должен быть %d байт", KeyLen)
	}
	if len(blob) < headerLen+nonceLen+16 || string(blob[:len(Magic)]) != Magic {
		return Envelope{}, errors.New("это не share-блоб sec")
	}
	if blob[len(Magic)] != Version {
		return Envelope{}, fmt.Errorf("версия блоба %d не поддерживается", blob[len(Magic)])
	}
	gcm, err := newGCM(key)
	if err != nil {
		return Envelope{}, err
	}
	plain, err := gcm.Open(nil, blob[headerLen:headerLen+nonceLen], blob[headerLen+nonceLen:], blob[:headerLen])
	if err != nil {
		return Envelope{}, errors.New("расшифровка не удалась — ключ не подходит к блобу")
	}
	var env Envelope
	if err := json.Unmarshal(plain, &env); err != nil {
		return Envelope{}, err
	}
	if env.V != Version {
		return Envelope{}, fmt.Errorf("версия конверта %d не поддерживается", env.V)
	}
	return env, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// SecretURL собирает ссылку: ключ — во фрагменте, браузер не отправляет его
// серверу ни в одном запросе.
func SecretURL(baseURL, id string, key []byte) string {
	return strings.TrimRight(baseURL, "/") + "/s/" + id + "#" + base64.RawURLEncoding.EncodeToString(key)
}

// IDFromURL вырезает id из полной ссылки (…/s/<id>#…); голый id — как есть.
func IDFromURL(s string) string {
	if i := strings.IndexByte(s, '#'); i >= 0 {
		s = s[:i]
	}
	if i := strings.Index(s, "/s/"); i >= 0 {
		s = s[i+3:]
	}
	return strings.Trim(s, "/")
}
