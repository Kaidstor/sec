package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func validBlob(size int) []byte {
	blob := append([]byte(blobMagic), 1)
	pad := size - len(blob)
	if pad < 12+16 {
		pad = 12 + 16
	}
	return append(blob, make([]byte, pad)...)
}

func newTestServer(t *testing.T) (*Server, *http.ServeMux, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := NewStorage(dir)
	if err != nil {
		t.Fatal(err)
	}
	tf := NewTokenFile(dir)
	token, err := tf.Issue("kai")
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(st, tf, 1024, 168*time.Hour)
	return srv, srv.Mux(), token
}

func do(mux *http.ServeMux, method, path, token string, body any) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

func createSecret(t *testing.T, mux *http.ServeMux, token string, ttl int64, once bool) (id, expiresAt string) {
	t.Helper()
	w := do(mux, "POST", "/api/v1/secrets", token,
		map[string]any{"blob": validBlob(64), "ttl": ttl, "once": once})
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var resp struct{ ID, ExpiresAt string }
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp.ID, resp.ExpiresAt
}

func TestCreateRequiresAuth(t *testing.T) {
	_, mux, _ := newTestServer(t)
	for _, token := range []string{"", "sst_fake"} {
		w := do(mux, "POST", "/api/v1/secrets", token,
			map[string]any{"blob": validBlob(64), "ttl": 60, "once": true})
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("token=%q: %d, want 401", token, w.Code)
		}
	}
}

func TestOnceFlow(t *testing.T) {
	_, mux, token := newTestServer(t)
	id, _ := createSecret(t, mux, token, 60, true)

	w := do(mux, "POST", "/api/v1/secrets/"+id+"/claim", "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("claim: %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		Blob []byte `json:"blob"`
		Once bool   `json:"once"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Once || !bytes.Equal(resp.Blob, validBlob(64)) {
		t.Fatal("клейм вернул не тот блоб или не пометил once")
	}

	if w := do(mux, "POST", "/api/v1/secrets/"+id+"/claim", "", nil); w.Code != http.StatusNotFound {
		t.Fatalf("повторный клейм: %d, want 404", w.Code)
	}
}

func TestMultiFlow(t *testing.T) {
	_, mux, token := newTestServer(t)
	id, _ := createSecret(t, mux, token, 60, false)

	for i := 0; i < 2; i++ {
		if w := do(mux, "POST", "/api/v1/secrets/"+id+"/claim", "", nil); w.Code != http.StatusOK {
			t.Fatalf("клейм %d: %d", i+1, w.Code)
		}
	}
	w := do(mux, "GET", "/api/v1/secrets", token, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d", w.Code)
	}
	var list struct {
		Secrets []struct {
			ID     string `json:"id"`
			Claims int    `json:"claims"`
		} `json:"secrets"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Secrets) != 1 || list.Secrets[0].Claims != 2 {
		t.Fatalf("list = %+v, want один секрет с claims=2", list.Secrets)
	}
}

func TestTTLCapped(t *testing.T) {
	_, mux, token := newTestServer(t)
	_, expiresAt := createSecret(t, mux, token, int64(365*24*3600), true)
	exp, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	want := time.Now().UTC().Add(168 * time.Hour)
	if d := exp.Sub(want); d < -time.Minute || d > time.Minute {
		t.Fatalf("expiresAt=%s — TTL не закапан до 168h", expiresAt)
	}
}

func TestCreateValidation(t *testing.T) {
	_, mux, token := newTestServer(t)

	if w := do(mux, "POST", "/api/v1/secrets", token,
		map[string]any{"blob": []byte("not-a-blob-but-long-enough-for-check"), "ttl": 60}); w.Code != http.StatusBadRequest {
		t.Fatalf("блоб без магии: %d, want 400", w.Code)
	}
	if w := do(mux, "POST", "/api/v1/secrets", token,
		map[string]any{"blob": validBlob(64), "ttl": 0}); w.Code != http.StatusBadRequest {
		t.Fatalf("ttl=0: %d, want 400", w.Code)
	}
	if w := do(mux, "POST", "/api/v1/secrets", token,
		map[string]any{"blob": validBlob(2048), "ttl": 60}); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("блоб сверх лимита: %d, want 413", w.Code)
	}
}

func TestListSeesOnlyOwn(t *testing.T) {
	srv, mux, token := newTestServer(t)
	token2, err := srv.tokens.Issue("other")
	if err != nil {
		t.Fatal(err)
	}
	createSecret(t, mux, token, 60, true)
	createSecret(t, mux, token2, 60, true)

	w := do(mux, "GET", "/api/v1/secrets", token, nil)
	var list struct {
		Secrets []struct {
			ID string `json:"id"`
		} `json:"secrets"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Secrets) != 1 {
		t.Fatalf("видно %d секретов, want 1 (только свои)", len(list.Secrets))
	}
}

func TestRevoke(t *testing.T) {
	srv, mux, token := newTestServer(t)
	token2, err := srv.tokens.Issue("other")
	if err != nil {
		t.Fatal(err)
	}
	id, _ := createSecret(t, mux, token, 60, true)

	if w := do(mux, "DELETE", "/api/v1/secrets/"+id, token2, nil); w.Code != http.StatusNotFound {
		t.Fatalf("отзыв чужого: %d, want 404", w.Code)
	}
	if w := do(mux, "DELETE", "/api/v1/secrets/"+id, token, nil); w.Code != http.StatusNoContent {
		t.Fatalf("отзыв своего: %d, want 204", w.Code)
	}
	if w := do(mux, "POST", "/api/v1/secrets/"+id+"/claim", "", nil); w.Code != http.StatusNotFound {
		t.Fatalf("клейм после отзыва: %d, want 404", w.Code)
	}
}

func TestRevealPageAlways200(t *testing.T) {
	_, mux, _ := newTestServer(t)
	w := do(mux, "GET", "/s/definitely-not-existing", "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("страница: %d, want 200 всегда (нет оракула существования)", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Показать секрет") {
		t.Fatal("страница без кнопки раскрытия")
	}
	if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") {
		t.Fatalf("нет строгого CSP: %q", csp)
	}
}

func TestClaimInvalidID(t *testing.T) {
	_, mux, _ := newTestServer(t)
	w := do(mux, "POST", "/api/v1/secrets/..%2Fetc/claim", "", nil)
	if w.Code == http.StatusOK {
		t.Fatalf("клейм кривого id прошёл: %d", w.Code)
	}
}

func TestClaimRateLimited(t *testing.T) {
	srv, mux, _ := newTestServer(t)
	srv.rl = NewRateLimiter(1) // burst = 1
	if w := do(mux, "POST", "/api/v1/secrets/"+NewID()+"/claim", "", nil); w.Code != http.StatusNotFound {
		t.Fatalf("первый клейм: %d, want 404", w.Code)
	}
	if w := do(mux, "POST", "/api/v1/secrets/"+NewID()+"/claim", "", nil); w.Code != http.StatusTooManyRequests {
		t.Fatalf("второй клейм: %d, want 429", w.Code)
	}
}

func TestPerTokenQuota(t *testing.T) {
	_, mux, token := newTestServer(t)
	for i := 0; i < maxLinksPerToken; i++ {
		createSecret(t, mux, token, 3600, true)
	}
	w := do(mux, "POST", "/api/v1/secrets", token,
		map[string]any{"blob": validBlob(64), "ttl": 3600, "once": true})
	if w.Code != http.StatusForbidden {
		t.Fatalf("создание сверх квоты: %d, want 403", w.Code)
	}
}

// Гигантский ttl не должен переполнять Duration (ссылка рождалась бы мёртвой).
func TestTTLOverflowClamped(t *testing.T) {
	_, mux, token := newTestServer(t)
	_, expiresAt := createSecret(t, mux, token, int64(1)<<62, true)
	exp, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if !exp.After(time.Now().UTC()) {
		t.Fatalf("expiresAt в прошлом: %s — переполнение TTL", expiresAt)
	}
}

// Последний адрес XFF добавлен ближайшим прокси; первый спуфится клиентом.
func TestClientIPTakesLastXFF(t *testing.T) {
	req := httptest.NewRequest("POST", "/x", nil)
	req.Header.Set("X-Forwarded-For", "6.6.6.6, 10.0.0.9")
	if ip := clientIP(req); ip != "10.0.0.9" {
		t.Fatalf("clientIP = %q, want последний адрес 10.0.0.9", ip)
	}
	req.Header.Del("X-Forwarded-For")
	if ip := clientIP(req); ip == "" {
		t.Fatal("clientIP пуст без XFF")
	}
}

func TestHealthz(t *testing.T) {
	_, mux, _ := newTestServer(t)
	if w := do(mux, "GET", "/healthz", "", nil); w.Code != http.StatusOK {
		t.Fatalf("healthz: %d", w.Code)
	}
}

func TestIndexPage(t *testing.T) {
	_, mux, _ := newTestServer(t)
	w := do(mux, "GET", "/", "", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "sec share") {
		t.Fatalf("корень: %d", w.Code)
	}
	// {$} держит остальные пути честным 404
	if w := do(mux, "GET", "/nope", "", nil); w.Code != http.StatusNotFound {
		t.Fatalf("/nope: %d, want 404", w.Code)
	}
}

func TestNoStoreOnAPI(t *testing.T) {
	_, mux, token := newTestServer(t)
	id, _ := createSecret(t, mux, token, 60, false)
	w := do(mux, "POST", fmt.Sprintf("/api/v1/secrets/%s/claim", id), "", nil)
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", cc)
	}
}
