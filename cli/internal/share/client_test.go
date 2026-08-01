package share

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClientCreate(t *testing.T) {
	var gotAuth string
	var gotReq struct {
		Blob []byte `json:"blob"`
		TTL  int64  `json:"ttl"`
		Once bool   `json:"once"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/v1/secrets" {
			t.Errorf("неожиданный запрос %s %s", r.Method, r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&gotReq)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"id": "Ab12", "expiresAt": "2026-08-02T10:00:00Z",
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL+"/", "sst_test")
	id, exp, err := c.Create([]byte("blob-bytes"), 24*time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	if id != "Ab12" || !exp.Equal(time.Date(2026, 8, 2, 10, 0, 0, 0, time.UTC)) {
		t.Fatalf("Create = (%q, %s)", id, exp)
	}
	if gotAuth != "Bearer sst_test" {
		t.Fatalf("Authorization = %q", gotAuth)
	}
	if string(gotReq.Blob) != "blob-bytes" || gotReq.TTL != 86400 || !gotReq.Once {
		t.Fatalf("тело запроса: %+v", gotReq)
	}
}

func TestClientUnauthorizedHint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "нужен токен"})
	}))
	defer srv.Close()

	_, err := NewClient(srv.URL, "bad").List()
	if err == nil || !strings.Contains(err.Error(), "sec share setup") {
		t.Fatalf("нет подсказки про setup: %v", err)
	}
}

func TestClientListAndRevoke(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /api/v1/secrets":
			_ = json.NewEncoder(w).Encode(map[string]any{"secrets": []map[string]any{{
				"id": "x1", "createdAt": "2026-08-01T10:00:00Z",
				"expiresAt": "2026-08-02T10:00:00Z", "once": true, "claims": 0,
			}}})
		case "DELETE /api/v1/secrets/x1":
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "нет такой ссылки"})
		}
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "sst_test")
	links, err := c.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 1 || links[0].ID != "x1" || !links[0].Once {
		t.Fatalf("List = %+v", links)
	}
	if err := c.Revoke("x1"); err != nil {
		t.Fatal(err)
	}
	if err := c.Revoke("nope"); err == nil {
		t.Fatal("Revoke несуществующего прошёл")
	}
}
