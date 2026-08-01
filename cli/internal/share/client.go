package share

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client — клиент HTTP API sec-share. Токен уходит только в заголовок
// Authorization; из секретного здесь бывает лишь готовый шифроблоб.
type Client struct {
	BaseURL string
	Token   string
	HC      *http.Client
}

func NewClient(baseURL, token string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Token:   token,
		// с запасом на аплоад ~5.6-МиБ блоба по медленному каналу
		HC: &http.Client{Timeout: 2 * time.Minute},
	}
}

type LinkInfo struct {
	ID        string
	CreatedAt time.Time
	ExpiresAt time.Time
	Once      bool
	Claims    int
}

func (c *Client) do(method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, c.BaseURL+path, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	resp, err := c.HC.Do(req)
	if err != nil {
		return fmt.Errorf("сервер %s недоступен: %w", c.BaseURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return c.apiError(resp)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (c *Client) apiError(resp *http.Response) error {
	var e struct {
		Error string `json:"error"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&e)
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return errors.New("сервер не принял токен — переподключись: sec share setup " + c.BaseURL)
	case http.StatusRequestEntityTooLarge:
		if e.Error != "" {
			return errors.New(e.Error)
		}
		return errors.New("секрет слишком большой для этого сервера")
	}
	if e.Error != "" {
		return fmt.Errorf("сервер ответил %d: %s", resp.StatusCode, e.Error)
	}
	return fmt.Errorf("сервер ответил %d", resp.StatusCode)
}

func (c *Client) Create(blob []byte, ttl time.Duration, once bool) (string, time.Time, error) {
	var resp struct {
		ID        string `json:"id"`
		ExpiresAt string `json:"expiresAt"`
	}
	err := c.do("POST", "/api/v1/secrets", map[string]any{
		"blob": blob, "ttl": int64(ttl.Seconds()), "once": once,
	}, &resp)
	if err != nil {
		return "", time.Time{}, err
	}
	exp, err := time.Parse(time.RFC3339, resp.ExpiresAt)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("сервер вернул кривой expiresAt %q", resp.ExpiresAt)
	}
	return resp.ID, exp, nil
}

func (c *Client) List() ([]LinkInfo, error) {
	var resp struct {
		Secrets []struct {
			ID        string `json:"id"`
			CreatedAt string `json:"createdAt"`
			ExpiresAt string `json:"expiresAt"`
			Once      bool   `json:"once"`
			Claims    int    `json:"claims"`
		} `json:"secrets"`
	}
	if err := c.do("GET", "/api/v1/secrets", nil, &resp); err != nil {
		return nil, err
	}
	out := make([]LinkInfo, 0, len(resp.Secrets))
	for _, s := range resp.Secrets {
		created, _ := time.Parse(time.RFC3339, s.CreatedAt)
		expires, _ := time.Parse(time.RFC3339, s.ExpiresAt)
		out = append(out, LinkInfo{
			ID: s.ID, CreatedAt: created, ExpiresAt: expires,
			Once: s.Once, Claims: s.Claims,
		})
	}
	return out, nil
}

func (c *Client) Revoke(id string) error {
	return c.do("DELETE", "/api/v1/secrets/"+url.PathEscape(id), nil, nil)
}
