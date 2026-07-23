package totp

import (
	"strings"
	"testing"
	"time"
)

// Векторы из RFC 6238 Appendix B: seed = ASCII "12345678901234567890"
// (base32: GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ), SHA1, period 30.
func TestTOTPRFC6238(t *testing.T) {
	seed := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	cases := []struct {
		raw  string
		unix int64
		want string
	}{
		{seed, 59, "287082"}, // 8-значный из RFC: 94287082
		{seed, 1111111109, "081804"},
		{seed, 1234567890, "005924"},
		{"otpauth://totp/x?secret=" + seed + "&digits=8", 59, "94287082"},
		{"otpauth://totp/x?secret=" + seed + "&digits=8", 2000000000, "69279037"},
		// нормализация: пробелы и нижний регистр
		{"gezd gnbv gy3t qojq gezd gnbv gy3t qojq", 59, "287082"},
	}
	for _, c := range cases {
		got, _, err := Code(c.raw, time.Unix(c.unix, 0))
		if err != nil {
			t.Fatalf("Code(%q, %d): %v", c.raw, c.unix, err)
		}
		if got != c.want {
			t.Errorf("Code(%q, %d) = %s, want %s", c.raw, c.unix, got, c.want)
		}
	}
}

func TestTOTPBadSeed(t *testing.T) {
	if _, _, err := Code("не base32 вообще!!!", time.Unix(59, 0)); err == nil {
		t.Error("ожидалась ошибка на некорректном seed")
	}
}

// Векторы из RFC 4226 Appendix D: seed = ASCII "12345678901234567890",
// счётчики 0..9.
func TestHOTPRFC4226(t *testing.T) {
	seed := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	want := []string{"755224", "287082", "359152", "969429", "338314",
		"254676", "287922", "162583", "399871", "520489"}
	uri := "otpauth://hotp/x?secret=" + seed + "&counter=0"
	for i, w := range want {
		code, next, counter, err := HOTPCode(uri)
		if err != nil {
			t.Fatalf("HOTPCode(#%d): %v", i, err)
		}
		if code != w {
			t.Errorf("HOTPCode(counter=%d) = %s, want %s", i, code, w)
		}
		if counter != uint64(i) {
			t.Errorf("counter = %d, want %d", counter, i)
		}
		uri = next // счётчик должен сдвинуться на 1
	}
}

func TestHOTPCounterFromURI(t *testing.T) {
	seed := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	// счётчик из середины серии — код должен совпасть с вектором RFC для 7
	code, next, counter, err := HOTPCode("otpauth://hotp/x?secret=" + seed + "&counter=7")
	if err != nil {
		t.Fatal(err)
	}
	if code != "162583" || counter != 7 {
		t.Errorf("code=%s counter=%d, want 162583/7", code, counter)
	}
	if !strings.Contains(next, "counter=8") {
		t.Errorf("next URI без counter=8: %s", next)
	}
}

func TestIsHOTP(t *testing.T) {
	cases := map[string]bool{
		"otpauth://hotp/x?secret=AAAA&counter=0": true,
		"otpauth://hotp?secret=AAAA":             true,
		"OTPAUTH://HOTP/x?secret=AAAA":           true,
		"otpauth://totp/x?secret=AAAA":           false,
		"otpauth://hotpX/x?secret=AAAA":          false,
		"GEZDGNBVGY3TQOJQ":                       false,
	}
	for raw, want := range cases {
		if got := IsHOTP(raw); got != want {
			t.Errorf("IsHOTP(%q) = %v, want %v", raw, got, want)
		}
	}
}

// Code() не должен молча считать «TOTP» от HOTP-URI — это рассинхронизировало
// бы счётчик с сервером.
func TestCodeRejectsHOTP(t *testing.T) {
	if _, _, err := Code("otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQ&counter=3", time.Unix(59, 0)); err == nil {
		t.Error("ожидалась ошибка: Code() получил HOTP-URI")
	}
}

// Битый или отсутствующий счётчик не должен молча превращаться в 0 —
// это выдало бы неверный код и перезаписало URI как counter=1.
func TestHOTPCounterValidation(t *testing.T) {
	seed := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	bad := []string{
		"otpauth://hotp/x?secret=" + seed,                                   // counter отсутствует
		"otpauth://hotp/x?secret=" + seed + "&counter=abc",                  // не число
		"otpauth://hotp/x?secret=" + seed + "&counter=-1",                   // отрицательный
		"otpauth://hotp/x?secret=" + seed + "&counter=18446744073709551615", // MaxUint64: инкремент обернулся бы в 0
	}
	for _, uri := range bad {
		if _, _, _, err := HOTPCode(uri); err == nil {
			t.Errorf("HOTPCode(%q): ожидалась ошибка", uri)
		}
	}
	// у TOTP-URI счётчик не обязателен и игнорируется
	if _, _, err := Code("otpauth://totp/x?secret="+seed+"&counter=abc", time.Unix(59, 0)); err != nil {
		t.Errorf("TOTP не должен требовать counter: %v", err)
	}
}

// QR-коды в алфанумерик-режиме отдают URI целиком в верхнем регистре — разбор
// (префикс, имена query-параметров) обязан быть регистронезависимым, как IsHOTP.
func TestUppercaseURIs(t *testing.T) {
	seed := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

	lo, _, _, err := HOTPCode("otpauth://hotp/x?secret=" + seed + "&counter=5")
	if err != nil {
		t.Fatal(err)
	}
	up, next, counter, err := HOTPCode("OTPAUTH://HOTP/X?SECRET=" + seed + "&COUNTER=5")
	if err != nil {
		t.Fatalf("верхнерегистровый HOTP-URI: %v", err)
	}
	if up != lo || counter != 5 {
		t.Errorf("code=%s counter=%d, ожидались %s/5", up, counter, lo)
	}
	if !strings.Contains(next, "counter=6") || strings.Contains(next, "COUNTER=") {
		t.Errorf("next должен содержать единственный counter=6: %s", next)
	}

	tlo, _, err := Code("otpauth://totp/x?secret="+seed, time.Unix(59, 0))
	if err != nil {
		t.Fatal(err)
	}
	tup, _, err := Code("OTPAUTH://TOTP/X?SECRET="+seed, time.Unix(59, 0))
	if err != nil {
		t.Fatalf("верхнерегистровый TOTP-URI: %v", err)
	}
	if tup != tlo {
		t.Errorf("TOTP: %s != %s", tup, tlo)
	}
}
