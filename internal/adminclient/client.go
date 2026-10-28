// Package adminclient is the HTTP client for the admin API.
// The CLI and the terminal UI both use it, so a running server stays
// the only writer of SQLite.
package adminclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Client calls the admin API with the admin token.
type Client struct {
	Base  string
	Token string
	HTTP  *http.Client
}

// APIError is a non-2xx admin response. Error returns the raw body so
// existing CLI output stays the response text.
type APIError struct {
	Status  int
	Code    string
	Message string
	Body    []byte
}

func (e *APIError) Error() string {
	if e == nil {
		return ""
	}
	if len(bytes.TrimSpace(e.Body)) == 0 {
		return fmt.Sprintf("admin API status %d", e.Status)
	}
	return strings.TrimSpace(string(e.Body))
}

// New returns a client for base. base is an http(s) URL, or unix:///path
// for an admin API on a Unix socket.
func New(base, token string) *Client {
	path, ok := UnixPath(base)
	if !ok {
		return &Client{
			Base:  strings.TrimRight(base, "/"),
			Token: token,
			HTTP:  &http.Client{Timeout: 30 * time.Second},
		}
	}
	dialer := &net.Dialer{}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", path)
		},
	}
	return &Client{
		Base:  "http://keman",
		Token: token,
		HTTP:  &http.Client{Timeout: 30 * time.Second, Transport: tr},
	}
}

// UnixPath returns the socket path for a unix:// or unix: base.
func UnixPath(base string) (string, bool) {
	switch {
	case strings.HasPrefix(base, "unix://"):
		return strings.TrimPrefix(base, "unix://"), true
	case strings.HasPrefix(base, "unix:"):
		return strings.TrimPrefix(base, "unix:"), true
	default:
		return "", false
	}
}

// Call sends one JSON request. out may be nil.
func (c *Client) Call(ctx context.Context, method, path string, in any, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		apiErr := &APIError{Status: resp.StatusCode, Body: raw}
		var wire struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(raw, &wire) == nil {
			apiErr.Code = wire.Error.Code
			apiErr.Message = wire.Error.Message
		}
		return apiErr
	}
	if out == nil || len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	return json.Unmarshal(raw, out)
}
