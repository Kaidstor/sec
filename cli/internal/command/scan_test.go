package command

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/kaidstor/sec/internal/store"
)

// Файловые секреты (PEM-ключи) многострочные — построчный матчинг их никогда
// не найдёт, scan обязан искать их по тексту целиком.
func TestScanReaderMultiline(t *testing.T) {
	pem := "-----BEGIN KEY-----\nAAAA\nBBBB\n-----END KEY-----\n"
	values := map[string][]string{
		pem:                        {"app/TLS_KEY"},
		"single-line-secret-value": {"app/TOKEN"},
	}
	text := "header\n" + pem + "tail single-line-secret-value\n"

	leaks := scanReader("t.txt", strings.NewReader(text), values)
	got := map[string]string{}
	for _, l := range leaks {
		got[l.loc] = strings.Join(l.refs, ",")
	}
	if got["t.txt:2"] != "app/TLS_KEY" {
		t.Errorf("многострочный секрет со строки 2 не найден: %v", got)
	}
	if got["t.txt:6"] != "app/TOKEN" {
		t.Errorf("однострочный секрет на строке 6 не найден: %v", got)
	}
}

// Вставленный без финального перевода строки файл — тоже утечка.
func TestScanReaderMultilineNoTrailingNewline(t *testing.T) {
	pem := "-----BEGIN KEY-----\nAAAA\n-----END KEY-----\n"
	leaks := scanReader("x", strings.NewReader("-----BEGIN KEY-----\nAAAA\n-----END KEY-----"),
		map[string][]string{pem: {"app/KEY"}})
	if len(leaks) != 1 || leaks[0].loc != "x:1" {
		t.Errorf("ожидалась одна утечка x:1, получено %+v", leaks)
	}
}

// Бинарный секрет в сторе лежит base64, а на диск утекает исходными байтами —
// scanData обязан находить сами байты, в том числе внутри бинарного файла
// (построчный текстовый скан такой файл пропускает целиком).
func TestScanDataBinary(t *testing.T) {
	raw := string([]byte{0x30, 0x82, 0x00, 0x01, 0xFF, 0xFE, 0x42, 0x99})
	bins := map[string][]string{raw: {"keys/P12"}}

	leaked := append([]byte("мусор до "), append([]byte(raw), []byte(" и после")...)...)
	leaks := scanData("keys.p12", leaked, nil, bins)
	if len(leaks) != 1 || leaks[0].loc != "keys.p12" || leaks[0].refs[0] != "keys/P12" {
		t.Errorf("бинарная утечка не найдена: %+v", leaks)
	}

	if leaks := scanData("clean.bin", []byte{0x00, 0x01, 0x02}, nil, bins); len(leaks) != 0 {
		t.Errorf("ложное срабатывание на чистом бинарнике: %+v", leaks)
	}
}

// Текстовый файл сканируется и на текстовые значения, и на бинарные байты
// (бинарь могли вклеить глубже первых 512 байт «текста»).
func TestScanDataMixed(t *testing.T) {
	raw := string([]byte{0xC3, 0x28, 0x00, 0x01}) // невалидный UTF-8 + NUL
	values := map[string][]string{"plain-secret-value": {"app/TOKEN"}}
	bins := map[string][]string{raw: {"keys/BLOB"}}

	data := []byte(strings.Repeat("padding line\n", 50) + "x plain-secret-value y\n" + raw)
	leaks := scanData("mix.txt", data, values, bins)
	got := map[string]bool{}
	for _, l := range leaks {
		got[strings.Join(l.refs, ",")] = true
	}
	if !got["keys/BLOB"] || !got["app/TOKEN"] {
		t.Errorf("ожидались обе утечки (текстовая и бинарная): %+v", leaks)
	}
}

// collectBinaryValues декодирует base64 и учитывает историю (~prev).
func TestCollectBinaryValues(t *testing.T) {
	raw, old := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}, []byte{0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8}
	b64 := func(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
	st := &store.Store{Projects: map[string]map[string]store.Secret{
		"keys": {
			"P12": {Value: b64(raw), Enc: store.EncB64,
				History: []store.Version{{Value: b64(old), Enc: store.EncB64, UpdatedAt: "2026-01-01T00:00:00Z"}}},
			"TXT": {Value: "просто текстовое значение"},
		},
	}}
	bins := collectBinaryValues(st, 4, false)
	if len(bins) != 1 || bins[string(raw)] == nil {
		t.Errorf("ожидались только текущие сырые байты: %v ключей", len(bins))
	}
	bins = collectBinaryValues(st, 4, true)
	if len(bins) != 2 || bins[string(old)][0] != "keys/P12~prev" {
		t.Errorf("история должна попадать с ~prev: %+v", refsOf(bins))
	}
	if bins := collectBinaryValues(st, 100, true); len(bins) != 0 {
		t.Errorf("короче minLen — отбрасывается: %v", refsOf(bins))
	}
}

func refsOf(m map[string][]string) [][]string {
	var out [][]string
	for _, refs := range m {
		out = append(out, refs)
	}
	return out
}
