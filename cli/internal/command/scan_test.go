package command

import (
	"strings"
	"testing"
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
