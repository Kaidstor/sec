package backup

import (
	"crypto/rand"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// ---------------------------------------------------------------------------
// Переносной бэкап: весь стор одним файлом под passphrase — для переноса на
// машину без Keychain. Формат:
//
//	"SECBAK03" + mem(4 BE) + time(4 BE) + par(1) + salt(16) + nonce(24)
//	          + XChaCha20-Poly1305(JSON стора)
//
// Ключ выводится Argon2id (memory-hard) с параметрами из заголовка, AAD —
// весь заголовок до nonce. Параметры лежат в файле, поэтому их можно поднимать,
// не ломая уже сделанные блобы. XChaCha20 — 192-битный nonce, случайный nonce
// безопасен без учёта числа сообщений.
// ---------------------------------------------------------------------------

const (
	backupMagic = "SECBAK03"
	// Параметры Argon2id — ориентир выше минимумов OWASP; для нечастой операции
	// бэкапа это доли секунды.
	argonMemKiB     uint32 = 64 * 1024 // 64 МиБ
	argonTime       uint32 = 3
	argonPar        uint8  = 4
	backupHeaderLen        = 8 + 4 + 4 + 1 + 16 // magic + mem + time + par + salt = 33
)

// Seal шифрует plaintext под passphrase в переносной блоб (Argon2id + XChaCha20).
func Seal(plaintext []byte, passphrase string) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	header := make([]byte, 0, backupHeaderLen)
	header = append(header, backupMagic...)
	header = binary.BigEndian.AppendUint32(header, argonMemKiB)
	header = binary.BigEndian.AppendUint32(header, argonTime)
	header = append(header, argonPar)
	header = append(header, salt...)

	key := argon2.IDKey([]byte(passphrase), salt, argonTime, argonMemKiB, argonPar, 32)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append(append([]byte(nil), header...), nonce...)
	return aead.Seal(out, nonce, plaintext, header), nil
}

// Open расшифровывает блоб, сделанный Seal, по passphrase.
func Open(data []byte, passphrase string) ([]byte, error) {
	if len(data) < backupHeaderLen+chacha20poly1305.NonceSizeX || string(data[:8]) != backupMagic {
		return nil, errors.New("не похоже на бэкап sec")
	}
	mem := binary.BigEndian.Uint32(data[8:12])
	t := binary.BigEndian.Uint32(data[12:16])
	par := data[16]
	// границы, чтобы враждебный/битый заголовок не заставил Argon2 съесть всю память
	if mem < 8*1024 || mem > 4*1024*1024 || t == 0 || t > 64 || par == 0 {
		return nil, errors.New("бэкап повреждён: некорректные параметры Argon2")
	}
	header, salt := data[:backupHeaderLen], data[17:backupHeaderLen]

	key := argon2.IDKey([]byte(passphrase), salt, t, mem, par, 32)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	head := backupHeaderLen + aead.NonceSize()
	nonce, ct := data[backupHeaderLen:head], data[head:]
	pt, err := aead.Open(nil, nonce, ct, header)
	if err != nil {
		return nil, errors.New("неверная passphrase или файл повреждён")
	}
	return pt, nil
}
