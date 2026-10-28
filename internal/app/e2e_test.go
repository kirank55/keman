package app_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kirank55/keman/internal/alert"
	"github.com/kirank55/keman/internal/app"
	"github.com/kirank55/keman/internal/cli"
	"github.com/kirank55/keman/internal/clock"
	"github.com/kirank55/keman/internal/config"
	"github.com/kirank55/keman/internal/model"
)

func TestEndToEnd(t *testing.T) {
	var got http.Header
	var query string
	var body []byte
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		query = r.URL.RawQuery
		body, _ = io.ReadAll(r.Body)
		switch r.URL.Path {
		case "/v1/chat/completions":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"usage":{"prompt_tokens":1000000,"completion_tokens":0}}`)
		default:
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"ok":true}`)
		}
	}))
	defer up.Close()

	logs := &syncBuf{}
	env := startStack(t, up.URL, nil, slog.New(slog.NewTextHandler(logs, nil)), nil)
	defer env.close()

	cred := env.api(t, http.MethodPost, "/v1/credentials", map[string]any{
		"upstream_id": env.upstream, "name": "primary", "auth_style": "header",
		"header_template": "Authorization: Bearer {key}", "secret": "sk-test-REALKEY-xyz",
	})
	key := env.api(t, http.MethodPost, "/v1/keys", map[string]any{"credential_id": cred["id"], "name": "laptop"})
	token := key["token"].(string)
	keyID := key["id"].(string)

	resp, raw := env.proxy(t, http.MethodGet, "/v1/models?a=1&b=2", token, nil, "")
	if resp.StatusCode != 200 {
		t.Fatalf("models %d %s", resp.StatusCode, raw)
	}
	if got.Get("Authorization") != "Bearer sk-test-REALKEY-xyz" {
		t.Fatalf("upstream auth %q", got.Get("Authorization"))
	}
	if got.Get("X-Forwarded-For") != "" || got.Get("X-Forwarded-Host") != "" || got.Get("Forwarded") != "" {
		t.Fatalf("forwarding headers leaked: %v", got)
	}
	if query != "a=1&b=2" {
		t.Fatalf("query %q", query)
	}
	if strings.Contains(logs.String(), token) || strings.Contains(logs.String(), "sk-test-REALKEY-xyz") {
		t.Fatalf("logs leaked secrets: %s", logs.String())
	}

	env.api(t, http.MethodPost, "/v1/keys/"+keyID+"/revoke", map[string]any{})
	resp, raw = env.proxy(t, http.MethodGet, "/v1/models", token, nil, "")
	if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("X-Keman-Error") != "key_revoked" {
		t.Fatalf("revoke %d %s %s", resp.StatusCode, resp.Header.Get("X-Keman-Error"), raw)
	}

	// Spend cap survives a restart. $1 of usage fills a $1 daily cap.
	capKey := env.api(t, http.MethodPost, "/v1/keys", map[string]any{"credential_id": cred["id"], "name": "capped"})
	capToken := capKey["token"].(string)
	capID := capKey["id"].(string)
	daily := int64(1_000_000)
	env.api(t, http.MethodPut, "/v1/keys/"+capID+"/policy", map[string]any{
		"mode": "alert_only", "daily_cap_microusd": daily,
	})
	resp, raw = env.proxy(t, http.MethodPost, "/v1/chat/completions", capToken, nil, `{"model":"test-model"}`)
	if resp.StatusCode != 200 {
		t.Fatalf("first spend %d %s", resp.StatusCode, raw)
	}
	env.close()
	env = startStack(t, up.URL, nil, nil, env)
	defer env.close()
	resp, raw = env.proxy(t, http.MethodPost, "/v1/chat/completions", capToken, nil, `{"model":"test-model"}`)
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get("X-Keman-Error") != "spend_cap_reached" {
		t.Fatalf("after restart %d %s %s body-to-up %s", resp.StatusCode, resp.Header.Get("X-Keman-Error"), raw, body)
	}

	// Untrusted peer: a spoofed X-Forwarded-For must not satisfy the allowlist.
	xffKey := env.api(t, http.MethodPost, "/v1/keys", map[string]any{"credential_id": cred["id"], "name": "xff"})
	env.api(t, http.MethodPut, "/v1/keys/"+xffKey["id"].(string)+"/policy", map[string]any{
		"mode": "alert_only", "cidrs": []string{"203.0.113.5/32"},
	})
	hdr := http.Header{"X-Forwarded-For": []string{"203.0.113.5"}, "X-Forwarded-Host": []string{"evil.example"}}
	resp, raw = env.proxy(t, http.MethodGet, "/v1/models", xffKey["token"].(string), hdr, "")
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get("X-Keman-Error") != "network_not_allowed" {
		t.Fatalf("xff %d %s %s", resp.StatusCode, resp.Header.Get("X-Keman-Error"), raw)
	}
}

func TestTrustedProxyUsesForwardedFor(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-For") != "" {
			t.Errorf("xff forwarded: %q", r.Header.Get("X-Forwarded-For"))
		}
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer up.Close()
	env := startStack(t, up.URL, []string{"127.0.0.1/32"}, nil, nil)
	defer env.close()
	cred := env.api(t, http.MethodPost, "/v1/credentials", map[string]any{
		"upstream_id": env.upstream, "name": "primary", "auth_style": "header",
		"header_template": "Authorization: Bearer {key}", "secret": "sk-trusted",
	})
	key := env.api(t, http.MethodPost, "/v1/keys", map[string]any{"credential_id": cred["id"], "name": "edge"})
	env.api(t, http.MethodPut, "/v1/keys/"+key["id"].(string)+"/policy", map[string]any{
		"mode": "alert_only", "cidrs": []string{"203.0.113.5/32"},
	})
	hdr := http.Header{"X-Forwarded-For": []string{"10.0.0.1, 203.0.113.5"}}
	resp, raw := env.proxy(t, http.MethodGet, "/v1/models", key["token"].(string), hdr, "")
	if resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, raw)
	}
}

func TestCanaryAlertWithinFiveSeconds(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("canary reached upstream")
	}))
	defer up.Close()
	got := make(chan []byte, 1)
	var hdr http.Header
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		hdr = r.Header.Clone()
		got <- b
		w.WriteHeader(http.StatusNoContent)
	}))
	defer hook.Close()
	env := startStack(t, up.URL, nil, nil, nil)
	defer env.close()
	env.api(t, http.MethodPost, "/v1/alerts", map[string]any{"kind": "webhook", "url": hook.URL, "secret": "whsec_test"})
	cred := env.api(t, http.MethodPost, "/v1/credentials", map[string]any{
		"upstream_id": env.upstream, "name": "primary", "auth_style": "header",
		"header_template": "Authorization: Bearer {key}", "secret": "sk-canary",
	})
	key := env.api(t, http.MethodPost, "/v1/keys", map[string]any{"credential_id": cred["id"], "name": "bird", "kind": "canary"})
	resp, raw := env.proxy(t, http.MethodPost, "/v1/chat/completions", key["token"].(string), nil, `{"model":"gpt-4o-mini"}`)
	if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("X-Keman-Error") != "" || strings.Contains(raw, "keman_error") {
		t.Fatalf("canary response %d %q %s", resp.StatusCode, resp.Header.Get("X-Keman-Error"), raw)
	}
	select {
	case b := <-got:
		sig := hdr.Get("X-Keman-Signature")
		ts, hexsig, ok := strings.Cut(strings.TrimPrefix(sig, "t="), ",v1=")
		if !ok {
			t.Fatalf("signature %q", sig)
		}
		unix, err := strconv.ParseInt(ts, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		if alert.HeaderValue("whsec_test", unix, b) != sig {
			t.Fatalf("bad signature %s body %s", sig, b)
		}
		_ = hexsig
		var payload map[string]any
		if err := json.Unmarshal(b, &payload); err != nil {
			t.Fatal(err)
		}
		if payload["rule"] != "canary_used" || payload["severity"] != "critical" {
			t.Fatalf("payload %s", b)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("canary alert was not delivered within 5s")
	}
}

func TestSpendFailClosed(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"usage":{"prompt_tokens":1,"completion_tokens":1}}`)
	}))
	defer up.Close()
	clk := clock.NewFake(time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC))
	env := startStack(t, up.URL, nil, nil, nil, withClock(clk))
	defer env.close()
	cred := env.api(t, http.MethodPost, "/v1/credentials", map[string]any{
		"upstream_id": env.upstream, "name": "primary", "auth_style": "header",
		"header_template": "Authorization: Bearer {key}", "secret": "sk-fail",
	})
	key := env.api(t, http.MethodPost, "/v1/keys", map[string]any{"credential_id": cred["id"], "name": "capped"})
	env.api(t, http.MethodPut, "/v1/keys/"+key["id"].(string)+"/policy", map[string]any{
		"mode": "alert_only", "daily_cap_microusd": int64(50_000_000),
	})
	resp, raw := env.proxy(t, http.MethodPost, "/v1/chat/completions", key["token"].(string), nil, `{"model":"test-model","max_tokens":1}`)
	if resp.StatusCode != 200 {
		t.Fatalf("warm %d %s", resp.StatusCode, raw)
	}
	env.waitDirtySpend(t)
	env.proc.SetSpendSaverForTest(func(context.Context, []model.SpendRow) error {
		return errors.New("disk")
	})
	env.proc.FlushSpendForTest()
	clk.Advance(61 * time.Second)
	resp, raw = env.proxy(t, http.MethodPost, "/v1/chat/completions", key["token"].(string), nil, `{"model":"test-model","max_tokens":1}`)
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("X-Keman-Error") != "store_unavailable" {
		t.Fatalf("fail closed %d %s %s", resp.StatusCode, resp.Header.Get("X-Keman-Error"), raw)
	}
}

func TestCLIInit(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := cli.Run(context.Background(), []string{"--config", filepath.Join(dir, "keman.yaml"), "init"}, func(k string) string {
		if k == "KEMAN_MASTER_KEY" {
			return "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
		}
		if k == "KEMAN_DATABASE" {
			return filepath.Join(dir, "keman.db")
		}
		return ""
	}, nil, &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "admin_token: kma_") {
		t.Fatalf("code %d\n%s\n%s", code, stdout.String(), stderr.String())
	}
	raw, err := os.ReadFile(filepath.Join(dir, "keman.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), filepath.Join(dir, "keman.db")) {
		t.Fatalf("init yaml missing database path:\n%s", raw)
	}
}

func TestOpenMissingDatabaseDoesNotCreateFile(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Database = filepath.Join(dir, "missing.db")
	cfg.ProxyListen = "127.0.0.1:0"
	cfg.AdminListen = "127.0.0.1:0"
	_, err := app.Open(context.Background(), cfg, bytes.Repeat([]byte{1}, 32))
	if err == nil || !strings.Contains(err.Error(), "not initialized") {
		t.Fatalf("err %v", err)
	}
	if _, err := os.Stat(cfg.Database); !os.IsNotExist(err) {
		t.Fatal("Open created a database file")
	}
}

func TestAdminRejectsEmptyNames(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer up.Close()
	env := startStack(t, up.URL, nil, nil, nil)
	defer env.close()
	body, _ := json.Marshal(map[string]any{"name": "", "profile": "openai", "host": "api.openai.com", "port": 443, "tls": true})
	req, err := http.NewRequest(http.MethodPost, env.admin+"/v1/upstreams", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+env.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(raw), "name") {
		t.Fatalf("%d %s", resp.StatusCode, raw)
	}
}

func TestCLIUnixAdmin(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "admin.sock")
	cfg := config.Defaults()
	cfg.Database = filepath.Join(dir, "keman.db")
	cfg.ProxyListen = "127.0.0.1:0"
	cfg.AdminListen = sock
	master := bytes.Repeat([]byte{7}, 32)
	token, err := app.Init(context.Background(), cfg, master)
	if err != nil {
		t.Fatal(err)
	}
	proc, err := app.Open(context.Background(), cfg, master)
	if err != nil {
		t.Fatal(err)
	}
	if err := proc.Start(); err != nil {
		t.Fatal(err)
	}
	defer proc.Close()
	if !strings.HasPrefix(proc.AdminURL(), "unix://") {
		t.Fatalf("admin url %s", proc.AdminURL())
	}
	var stdout, stderr bytes.Buffer
	code := cli.Run(context.Background(), []string{
		"--admin-url", proc.AdminURL(), "--admin-token", token, "upstream", "list",
	}, nil, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code %d\n%s\n%s", code, stdout.String(), stderr.String())
	}
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type stack struct {
	t        *testing.T
	proc     *app.App
	admin    string
	token    string
	upstream string
	cfg      config.Config
	master   []byte
	dir      string
	opts     []app.Option
	closed   bool
}

type optFn func(*boot)

type boot struct{ opts []app.Option }

func withClock(c clock.Clock) optFn {
	return func(b *boot) { b.opts = append(b.opts, app.WithClock(c)) }
}

func startStack(t *testing.T, upstream string, trusted []string, log *slog.Logger, reuse *stack, extra ...optFn) *stack {
	t.Helper()
	var b boot
	for _, fn := range extra {
		fn(&b)
	}
	if log != nil {
		b.opts = append(b.opts, app.WithLogger(log))
	}
	s := reuse
	if s == nil {
		dir := t.TempDir()
		prices := filepath.Join(dir, "prices.json")
		if err := os.WriteFile(prices, []byte(`{"version":"test","models":{"test-model":{"input":1000000,"output":1000000,"cached_input":500000}}}`), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg := config.Defaults()
		cfg.Database = filepath.Join(dir, "keman.db")
		cfg.ProxyListen = "127.0.0.1:0"
		cfg.AdminListen = "127.0.0.1:0"
		cfg.PricesFile = prices
		cfg.TrustedProxies = trusted
		cfg.SpendFlushInterval = time.Hour
		master := bytes.Repeat([]byte{9}, 32)
		token, err := app.Init(context.Background(), cfg, master)
		if err != nil {
			t.Fatal(err)
		}
		s = &stack{t: t, token: token, cfg: cfg, master: master, dir: dir, opts: b.opts}
	} else {
		s.opts = b.opts
		s.closed = false
	}
	proc, err := app.Open(context.Background(), s.cfg, s.master, s.opts...)
	if err != nil {
		t.Fatal(err)
	}
	if err := proc.Start(); err != nil {
		t.Fatal(err)
	}
	s.proc = proc
	s.admin = proc.AdminURL()
	if s.upstream == "" {
		u, err := url.Parse(upstream)
		if err != nil {
			t.Fatal(err)
		}
		port, _ := strconv.Atoi(u.Port())
		created := s.api(t, http.MethodPost, "/v1/upstreams", map[string]any{
			"name": "openai", "profile": "openai", "host": u.Hostname(), "port": port, "tls": false,
		})
		s.upstream = created["id"].(string)
	}
	return s
}

func (s *stack) waitDirtySpend(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if rows := s.proc.DirtySpendForTest(); len(rows) > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("spend was not recorded after proxy request")
		}
		time.Sleep(time.Millisecond)
	}
}

func (s *stack) close() {
	if s == nil || s.closed || s.proc == nil {
		return
	}
	s.closed = true
	if err := s.proc.Close(); err != nil {
		s.t.Errorf("close: %v", err)
	}
}

func (s *stack) api(t *testing.T, method, path string, body any) map[string]any {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, s.admin+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		t.Fatalf("%s %s -> %d %s", method, path, resp.StatusCode, raw)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("json %s: %v", raw, err)
	}
	return out
}

func (s *stack) proxy(t *testing.T, method, path, token string, hdr http.Header, body string) (*http.Response, string) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, s.proc.ProxyURL()+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp, string(raw)
}

func TestDetectionLiveProbe(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer up.Close()
	env := startStack(t, up.URL, nil, nil, nil)
	defer env.close()
	cred := env.api(t, http.MethodPost, "/v1/credentials", map[string]any{
		"upstream_id": env.upstream, "name": "primary", "auth_style": "header",
		"header_template": "Authorization: Bearer {key}", "secret": "sk-live-probe",
	})
	key := env.api(t, http.MethodPost, "/v1/keys", map[string]any{"credential_id": cred["id"], "name": "laptop"})
	token := key["token"].(string)
	path := filepath.Join(t.TempDir(), "virtual.key")
	if err := os.WriteFile(path, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := cli.Run(context.Background(), []string{
		"--admin-url", env.proc.AdminURL(),
		"--admin-token", env.token,
		"detection", "test", "--live",
		"--proxy", env.proc.ProxyURL(),
		"--secret-file", path,
	}, nil, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code %d\n%s\n%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "allowlist_violations medium") || !strings.Contains(stdout.String(), "count=5") {
		t.Fatalf("stdout\n%s\nstderr\n%s", stdout.String(), stderr.String())
	}
}
