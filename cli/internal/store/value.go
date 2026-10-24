package store

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"unicode/utf8"
)

// Value — значение одной версии ключа. Открытый текст отдаёт только Load:
// в формате SQLite значение лежит отдельным зашифрованным payload и читается
// из снимка, под которым открыт стор, поэтому незагруженное значение не может
// молча стать пустой строкой. Размеры и отпечаток лежат в каталоге и
// доступны без расшифровки payload.
type Value struct {
	text   string
	loaded bool
	id     string // payload в SQLite; "" — значение в памяти
	info   valueInfo
	src    *sqlStore
}

// valueInfo — несекретная сводка значения, считается при записи и хранится в
// зашифрованном каталоге: ls/history/diff/doctor работают без payload.
type valueInfo struct {
	Len   int    `json:"len"`   // байт в строке значения
	Runes int    `json:"runes"` // символов
	Raw   int    `json:"raw"`   // байт после base64 (для enc=b64)
	Sum   []byte `json:"sum"`   // HMAC-SHA256(мастер-ключ, значение)
}

var errNotLoaded = errors.New("значение не загружено (внутренняя ошибка sec)")

// Text — значение, заданное открытым текстом в памяти (set/gen/import/restore).
func Text(s string) Value { return Value{text: s, loaded: true} }

// Load возвращает открытый текст: из памяти или из payload снимка стора.
func (v Value) Load() (string, error) {
	if v.loaded {
		return v.text, nil
	}
	if v.id == "" || v.src == nil {
		return "", errNotLoaded
	}
	return v.src.load(v)
}

// Chars — длина значения в символах (без расшифровки).
func (v Value) Chars() int {
	if v.loaded {
		return utf8.RuneCountInString(v.text)
	}
	return v.info.Runes
}

// DecodedLen — размер исходных байт base64-значения без декодирования.
func (v Value) DecodedLen() int {
	if v.loaded {
		return decodedB64Len(v.text)
	}
	return v.info.Raw
}

// Fingerprint — отпечаток fp:… значения (см. store.Fingerprint) без
// расшифровки payload: в каталоге лежит полный HMAC.
func (v Value) Fingerprint(key []byte) string {
	if !v.loaded && v.info.Sum != nil {
		return "fp:" + hex.EncodeToString(v.info.Sum[:8])
	}
	return Fingerprint(key, v.text)
}

// MarshalJSON запрещает случайную сериализацию: Value без Load — не значение.
// Наружу стор уходит только через MarshalPortable.
func (Value) MarshalJSON() ([]byte, error) {
	return nil, errors.New("store.Value не сериализуется напрямую — MarshalPortable")
}

func (v Value) sum(key []byte) []byte {
	if !v.loaded && v.info.Sum != nil {
		return v.info.Sum
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(v.text))
	return mac.Sum(nil)
}

// equal — совпадают ли значения, по возможности без расшифровки.
func (v Value) equal(w Value) bool {
	if v.loaded && w.loaded {
		return v.text == w.text
	}
	key := v.srcKey()
	if key == nil {
		key = w.srcKey()
	}
	if key == nil {
		return false
	}
	return hmac.Equal(v.sum(key), w.sum(key))
}

func (v Value) srcKey() []byte {
	if v.src != nil {
		return v.src.key
	}
	return nil
}

func infoOf(text string, key []byte) valueInfo {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(text))
	return valueInfo{Len: len(text), Runes: utf8.RuneCountInString(text), Raw: decodedB64Len(text), Sum: mac.Sum(nil)}
}

// decodedB64Len — размер исходных байт по base64-строке, без декодирования.
func decodedB64Len(s string) int {
	pad := 0
	for i := len(s) - 1; i >= 0 && s[i] == '='; i-- {
		pad++
	}
	return len(s)/4*3 - pad
}
