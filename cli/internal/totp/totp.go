// Пакет totp — одноразовые коды: TOTP (RFC 6238, по времени) и HOTP
// (RFC 4226, по счётчику). TOTP — это HOTP от счётчика времени, поэтому
// ядро (hotp) общее. Секрет — base32-seed либо полный otpauth:// URI.
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
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// params — разобранные параметры OTP-секрета: сырой base32-seed с дефолтами
// либо otpauth:// URI (digits/period/algorithm/counter из query).
type params struct {
	secret  string
	digits  int
	period  int
	counter uint64
	algo    func() hash.Hash
	uri     *url.URL // не nil, только если raw был otpauth:// URI
}

// qGet — значение query-параметра без учёта регистра имени: QR-коды в
// алфанумерик-режиме отдают URI целиком в верхнем регистре (SECRET=, COUNTER=),
// как и IsHOTP, весь разбор обязан это принимать.
func qGet(q url.Values, name string) string {
	if v := q.Get(name); v != "" {
		return v
	}
	for k, vs := range q {
		if strings.EqualFold(k, name) && len(vs) > 0 {
			return vs[0]
		}
	}
	return ""
}

func parseRaw(raw string) (*params, error) {
	p := &params{secret: raw, digits: 6, period: 30, algo: sha1.New}
	// префикс — без учёта регистра, в паре с IsHOTP: иначе верхнерегистровый
	// URI ушёл бы в base32-декодер как «seed» и умер с невнятной ошибкой
	if !strings.HasPrefix(strings.ToLower(raw), "otpauth://") {
		return p, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("otpauth URI: %w", err)
	}
	q := u.Query()
	p.uri = u
	p.secret = qGet(q, "secret")
	if d, err := strconv.Atoi(qGet(q, "digits")); err == nil && d >= 6 && d <= 8 {
		p.digits = d
	}
	if per, err := strconv.Atoi(qGet(q, "period")); err == nil && per > 0 {
		p.period = per
	}
	// счётчик обязателен и валидируется только для hotp: молчаливый ноль на
	// битом counter выдал бы неверный код и перезаписал URI как counter=1
	if strings.EqualFold(u.Host, "hotp") {
		cs := qGet(q, "counter")
		c, cerr := strconv.ParseUint(cs, 10, 64)
		if cerr != nil {
			if cs == "" {
				return nil, errors.New("HOTP-URI без счётчика: нужен параметр counter=<число>")
			}
			return nil, fmt.Errorf("HOTP-счётчик counter=%q — не целое число ≥ 0", cs)
		}
		if c == math.MaxUint64 {
			return nil, errors.New("HOTP-счётчик исчерпан (2^64-1) — перевыпусти seed")
		}
		p.counter = c
	}
	if a := strings.ToUpper(qGet(q, "algorithm")); a != "" {
		algos := map[string]func() hash.Hash{"SHA1": sha1.New, "SHA256": sha256.New, "SHA512": sha512.New}
		if p.algo = algos[a]; p.algo == nil {
			return nil, fmt.Errorf("неподдерживаемый алгоритм %s", a)
		}
	}
	return p, nil
}

// key декодирует base32-seed (пробелы/дефисы/регистр/паддинг не важны).
func (p *params) key() ([]byte, error) {
	clean := strings.ToUpper(strings.NewReplacer(" ", "", "-", "").Replace(p.secret))
	clean = strings.TrimRight(clean, "=")
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(clean)
	if err != nil || len(key) == 0 {
		return nil, errors.New("значение не похоже на OTP-секрет (нужен base32-seed или otpauth:// URI)")
	}
	return key, nil
}

// hotp — ядро RFC 4226: HMAC(key, counter) → динамическое усечение → digits цифр.
func hotp(algo func() hash.Hash, key []byte, counter uint64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(algo, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, bin%mod)
}

// IsHOTP — значение является otpauth://hotp-URI (счётчиковый код, не временной).
func IsHOTP(raw string) bool {
	const prefix = "otpauth://hotp"
	l := strings.ToLower(raw)
	if !strings.HasPrefix(l, prefix) {
		return false
	}
	rest := l[len(prefix):]
	return rest == "" || rest[0] == '/' || rest[0] == '?'
}

// Code считает TOTP по RFC 6238. raw — base32-seed (пробелы/дефисы/регистр
// не важны) либо полный otpauth://totp URI (digits/period/algorithm
// учитываются). Возвращает код и сколько секунд он ещё действителен.
func Code(raw string, t time.Time) (string, int, error) {
	if IsHOTP(raw) {
		return "", 0, errors.New("это HOTP-секрет: код считается по счётчику, а не времени")
	}
	p, err := parseRaw(raw)
	if err != nil {
		return "", 0, err
	}
	key, err := p.key()
	if err != nil {
		return "", 0, err
	}
	code := hotp(p.algo, key, uint64(t.Unix())/uint64(p.period), p.digits)
	remain := p.period - int(t.Unix()%int64(p.period))
	return code, remain, nil
}

// HOTPCode считает HOTP по RFC 4226 из otpauth://hotp-URI. Возвращает код,
// URI с инкрементированным счётчиком (его нужно сохранить взамен старого —
// счётчик одноразовый) и использованное значение счётчика.
func HOTPCode(raw string) (code, next string, counter uint64, err error) {
	if !IsHOTP(raw) {
		return "", "", 0, errors.New("не HOTP-секрет (нужен otpauth://hotp-URI со счётчиком)")
	}
	p, err := parseRaw(raw)
	if err != nil {
		return "", "", 0, err
	}
	key, err := p.key()
	if err != nil {
		return "", "", 0, err
	}
	code = hotp(p.algo, key, p.counter, p.digits)
	q := p.uri.Query()
	for k := range q { // COUNTER=/Counter= — убираем все регистровые варианты, иначе останется два счётчика
		if strings.EqualFold(k, "counter") {
			q.Del(k)
		}
	}
	q.Set("counter", strconv.FormatUint(p.counter+1, 10))
	p.uri.RawQuery = q.Encode()
	return code, p.uri.String(), p.counter, nil
}
