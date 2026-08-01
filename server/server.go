package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Формат блоба (создаёт CLI, сервер проверяет только магию):
// "secshare" + байт версии + nonce(12) + AES-256-GCM ciphertext.
const (
	blobMagic     = "secshare"
	blobHeaderLen = len(blobMagic) + 1
	blobMinLen    = blobHeaderLen + 12 + 16 // + nonce + GCM-тег
)

var idRe = regexp.MustCompile(`^[0-9A-Za-z]{1,64}$`)

// maxLinksPerToken — активных ссылок на один токен-создатель.
const maxLinksPerToken = 100

// Существует / уже забран / протух — не различаем: нет оракула для перебора.
const claimGone = "ссылка не существует, уже открыта или истекла"

type Server struct {
	st      *Storage
	tokens  *TokenFile
	rl      *RateLimiter
	maxBlob int64
	maxTTL  time.Duration
	now     func() time.Time
}

func NewServer(st *Storage, tokens *TokenFile, maxBlob int64, maxTTL time.Duration) *Server {
	return &Server{
		st: st, tokens: tokens,
		rl:      NewRateLimiter(30),
		maxBlob: maxBlob, maxTTL: maxTTL,
		now: func() time.Time { return time.Now().UTC() },
	}
}

func (s *Server) Mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/secrets", s.handleCreate)
	mux.HandleFunc("POST /api/v1/secrets/{id}/claim", s.handleClaim)
	mux.HandleFunc("GET /api/v1/secrets", s.handleList)
	mux.HandleFunc("DELETE /api/v1/secrets/{id}", s.handleDelete)
	mux.HandleFunc("GET /s/{id}", s.handleReveal)
	mux.HandleFunc("GET /s/{id}/{$}", s.handleReveal) // мессенджеры дописывают хвостовой слэш
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	// {$} — только корень: остальные пути остаются честным 404
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		h := w.Header()
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write(indexHTML)
	})
	return mux
}

func (s *Server) auth(r *http.Request) (string, bool) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return "", false
	}
	return s.tokens.Verify(strings.TrimSpace(token))
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

type createRequest struct {
	Blob []byte `json:"blob"`
	TTL  int64  `json:"ttl"` // секунды
	Once bool   `json:"once"`
}

func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request) {
	name, ok := s.auth(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "нужен действующий токен (Authorization: Bearer …)")
		return
	}
	// блоб едет в JSON как base64 (×4/3) — лимит тела с запасом в полтора блоба
	r.Body = http.MaxBytesReader(w, r.Body, s.maxBlob+s.maxBlob/2+4096)
	var req createRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeErr(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("блоб больше лимита %d байт", s.maxBlob))
			return
		}
		writeErr(w, http.StatusBadRequest, "битый JSON")
		return
	}
	if int64(len(req.Blob)) > s.maxBlob {
		writeErr(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("блоб больше лимита %d байт", s.maxBlob))
		return
	}
	if len(req.Blob) < blobMinLen || !bytes.HasPrefix(req.Blob, []byte(blobMagic)) {
		writeErr(w, http.StatusBadRequest, "это не share-блоб sec")
		return
	}
	if req.TTL <= 0 {
		writeErr(w, http.StatusBadRequest, "ttl должен быть положительным (секунды)")
		return
	}
	// кап ДО умножения на time.Second: гигантский ttl от сырого клиента иначе
	// переполнил бы Duration в отрицательное — ссылка рождалась бы мёртвой
	if req.TTL > int64(s.maxTTL/time.Second) {
		req.TTL = int64(s.maxTTL / time.Second) // молча: честный expiresAt уходит в ответе
	}
	ttl := time.Duration(req.TTL) * time.Second
	// квота на токен: утёкший/разошедшийся токен не должен заливать диск
	if active, lerr := s.st.List(name); lerr == nil && len(active) >= maxLinksPerToken {
		writeErr(w, http.StatusForbidden,
			fmt.Sprintf("у токена уже %d активных ссылок — отзови ненужные (sec share revoke) или дождись истечения", len(active)))
		return
	}
	now := s.now()
	rec := SecretRecord{
		V: 1, ID: NewID(), Blob: req.Blob, Once: req.Once,
		TokenName: name, CreatedAt: now, ExpiresAt: now.Add(ttl),
	}
	if err := s.st.Save(rec); err != nil {
		writeErr(w, http.StatusInternalServerError, "не смог сохранить")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":        rec.ID,
		"expiresAt": rec.ExpiresAt.Format(time.RFC3339),
	})
}

func (s *Server) handleClaim(w http.ResponseWriter, r *http.Request) {
	if !s.rl.Allow(clientIP(r)) {
		writeErr(w, http.StatusTooManyRequests, "слишком часто — подожди минуту")
		return
	}
	id := r.PathValue("id")
	if !idRe.MatchString(id) {
		writeErr(w, http.StatusNotFound, claimGone)
		return
	}
	rec, ok := s.st.Claim(id)
	if !ok {
		writeErr(w, http.StatusNotFound, claimGone)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"blob": rec.Blob, "once": rec.Once})
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	name, ok := s.auth(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "нужен действующий токен (Authorization: Bearer …)")
		return
	}
	recs, err := s.st.List(name)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "не смог прочитать")
		return
	}
	type item struct {
		ID        string `json:"id"`
		CreatedAt string `json:"createdAt"`
		ExpiresAt string `json:"expiresAt"`
		Once      bool   `json:"once"`
		Claims    int    `json:"claims"`
	}
	items := make([]item, 0, len(recs))
	for _, rec := range recs {
		items = append(items, item{
			ID: rec.ID, Once: rec.Once, Claims: rec.Claims,
			CreatedAt: rec.CreatedAt.Format(time.RFC3339),
			ExpiresAt: rec.ExpiresAt.Format(time.RFC3339),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"secrets": items})
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	name, ok := s.auth(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "нужен действующий токен (Authorization: Bearer …)")
		return
	}
	id := r.PathValue("id")
	if !idRe.MatchString(id) || !s.st.Delete(id, name) {
		writeErr(w, http.StatusNotFound, "нет такой ссылки")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleReveal отдаёт статичную страницу всегда, не заглядывая в стор:
// существование ссылки не раскрывается, а превью-боты мессенджеров ничего не
// сжигают — секрет забирает только POST …/claim по клику получателя.
func (s *Server) handleReveal(w http.ResponseWriter, _ *http.Request) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	// object-src/frame-src blob: — иначе часть браузеров режет скачивание
	// расшифрованного файла по blob:-ссылке (как у PrivateBin);
	// frame-ancestors 'none' — кликджекинг на «Показать» сжёг бы once-ссылку
	h.Set("Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; "+
			"object-src blob:; frame-src blob:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Robots-Tag", "noindex")
	_, _ = w.Write(revealHTML)
}

// clientIP: сервер живёт за traefik — берётся ПОСЛЕДНИЙ адрес X-Forwarded-For
// (его дописал ближайший прокси; первый элемент клиент может подделать сам и
// обойти rate limit, наплодив заодно бакетов на каждый запрос). Без прокси —
// RemoteAddr.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[len(parts)-1])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
