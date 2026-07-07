package totp

import (
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
