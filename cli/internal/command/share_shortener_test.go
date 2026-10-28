package command

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// shareWithFakeK4tr создаёт ссылку через фейковый share-сервер и фейковый k4tr,
// который пишет свои аргументы в файл и отвечает заданным конвертом.
func shareWithFakeK4tr(t *testing.T, k4trReply string, k4trCode int) (map[string]any, []string, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("фейковый k4tr — sh-скрипт")
	}
	cliEnv(t)
	expires := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"id":"ExampleId0ExampleId012","expiresAt":%q}`, expires)
	}))
	t.Cleanup(srv.Close)
	bin := t.TempDir()
	argsFile := filepath.Join(bin, "args")
	script := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"$@\" > '%s'\nprintf '%%s\\n' '%s'\nexit %d\n", argsFile, k4trReply, k4trCode)
	if err := os.WriteFile(filepath.Join(bin, "k4tr"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("SEC_SHARE_URL", srv.URL)
	t.Setenv("SEC_SHARE_TOKEN", "test-token")
	t.Setenv("SEC_SHARE_SHORTENER", "k4tr")
	r := secProc(t, "value", "share", "-", "--no-clip", "--json")
	if r.code != 0 {
		t.Fatalf("share: код %d, stderr %q, stdout %q", r.code, r.stderr, r.stdout)
	}
	var env struct {
		Data    map[string]any `json:"data"`
		Warning []string       `json:"warning"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &env); err != nil {
		t.Fatalf("%v: %s", err, r.stdout)
	}
	raw, _ := os.ReadFile(argsFile)
	return env.Data, strings.Fields(string(raw)), strings.Join(env.Warning, "\n")
}

func TestShareShortensWithoutSendingKeyToK4tr(t *testing.T) {
	data, args, warning := shareWithFakeK4tr(t, `{"v":1,"data":{"short_url":"https://k4tr.ru/AbC234"},"error":null}`, 0)
	long, _ := data["longUrl"].(string)
	base, fragment, ok := strings.Cut(long, "#")
	if !ok || !strings.HasSuffix(base, "/s/ExampleId0ExampleId012") {
		t.Fatalf("longUrl = %q", long)
	}
	if data["url"] != "https://k4tr.ru/AbC234#"+fragment {
		t.Errorf("url = %v, ждали короткую ссылку с тем же фрагментом", data["url"])
	}
	if warning != "" {
		t.Errorf("лишнее предупреждение: %s", warning)
	}
	if len(args) != 6 || args[0] != "create" || args[1] != base || args[2] != "--multi" || args[3] != "--ttl" || args[5] != "--json" {
		t.Fatalf("аргументы k4tr: %q", args)
	}
	if ttl, _ := strconv.Atoi(args[4]); ttl < 3500 || ttl > 3600 {
		t.Errorf("--ttl %s, ждали срок share-ссылки ≈3600", args[4])
	}
	took, _ := data["tookMs"].(float64)
	shorten, ok := data["shortenMs"].(float64)
	if !ok || shorten > took {
		t.Errorf("tookMs=%v shortenMs=%v: время k4tr входит в общее", data["tookMs"], data["shortenMs"])
	}
}

func TestShareKeepsLongLinkWhenK4trFails(t *testing.T) {
	data, _, warning := shareWithFakeK4tr(t, `{"v":1,"data":null,"error":{"kind":"network","message":"Сервис недоступен"}}`, 2)
	if url, _ := data["url"].(string); !strings.Contains(url, "/s/ExampleId0ExampleId012#") {
		t.Errorf("url = %q, ждали полную ссылку", url)
	}
	if _, ok := data["longUrl"]; ok {
		t.Error("longUrl без укорачивания")
	}
	if !strings.Contains(warning, "Сервис недоступен") {
		t.Errorf("предупреждение: %q", warning)
	}
}

func TestShareSetupShortener(t *testing.T) {
	cliEnv(t)
	if r := secProc(t, "", "share", "setup", "--shortener", "k4tr"); r.code == 0 {
		t.Fatal("укорачиватель включился без настроенного сервера")
	}
	if r := secProc(t, "", "share", "setup", "--shortener", "bitly"); r.code != 2 {
		t.Fatalf("неизвестный укорачиватель: код %d", r.code)
	}
	if r := secProc(t, "", "share", "revoke", "https://k4tr.ru/AbC234#key"); r.code != 2 || !strings.Contains(r.stderr, "sec share ls") {
		t.Fatalf("revoke короткой ссылки: код %d, %q", r.code, r.stderr)
	}
}
