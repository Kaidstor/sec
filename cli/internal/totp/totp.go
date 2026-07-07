package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Code считает код по RFC 6238. raw — base32-seed (пробелы/дефисы/регистр
// не важны) либо полный otpauth:// URI (digits/period/algorithm учитываются).
// Возвращает код и сколько секунд он ещё действителен.
func Code(raw string, t time.Time) (string, int, error) {
	secret, digits, period := raw, 6, 30
	algo := sha1.New
	if strings.HasPrefix(raw, "otpauth://") {
		u, err := url.Parse(raw)
		if err != nil {
			return "", 0, fmt.Errorf("otpauth URI: %w", err)
		}
		q := u.Query()
		secret = q.Get("secret")
		if d, err := strconv.Atoi(q.Get("digits")); err == nil && d >= 6 && d <= 8 {
			digits = d
		}
		if p, err := strconv.Atoi(q.Get("period")); err == nil && p > 0 {
			period = p
		}
		if a := strings.ToUpper(q.Get("algorithm")); a != "" {
			algos := map[string]func() hash.Hash{"SHA1": sha1.New, "SHA256": sha256.New, "SHA512": sha512.New}
			if algo = algos[a]; algo == nil {
				return "", 0, fmt.Errorf("неподдерживаемый алгоритм %s", a)
			}
		}
	}
	clean := strings.ToUpper(strings.NewReplacer(" ", "", "-", "").Replace(secret))
	clean = strings.TrimRight(clean, "=")
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(clean)
	if err != nil || len(key) == 0 {
		return "", 0, errors.New("значение не похоже на TOTP-секрет (нужен base32-seed или otpauth:// URI)")
	}

	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(t.Unix())/uint64(period))
	mac := hmac.New(algo, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	code := fmt.Sprintf("%0*d", digits, bin%mod)
	remain := period - int(t.Unix()%int64(period))
	return code, remain, nil
}
