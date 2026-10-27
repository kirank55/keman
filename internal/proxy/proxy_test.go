package proxy_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kirank55/keman/internal/clock"
	"github.com/kirank55/keman/internal/keyfmt"
	"github.com/kirank55/keman/internal/model"
	"github.com/kirank55/keman/internal/money"
	"github.com/kirank55/keman/internal/price"
	"github.com/kirank55/keman/internal/proxy"
	"github.com/kirank55/keman/internal/redact"
	"github.com/kirank55/keman/internal/state"
)

const realKey = "sk-test-REALKEY-xyz"

type harness struct {
	state *state.State
	proxy *proxy.Proxy
	token string
	id    string
	logs  *lockedBuf
}

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func newHarness(t testing.TB, upstream string, prof string, paths []string) *harness {
	t.Helper()
	u, err := url.Parse(upstream)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(u.Port())
	st := state.New(clock.System{}, 60, time.Minute)
	up := model.Upstream{
		ID: "up_1", Name: "u", Protocol: model.ProtocolHTTP, Profile: prof,
		Host: u.Hostname(), Port: port, InjectUsage: true, PathAllowlist: paths,
	}
	st.PutUpstream(up)
	st.PutCredential(model.Credential{
		ID: "cred_1", UpstreamID: up.ID, Name: "c", AuthStyle: model.AuthHeader,
		HeaderTemplate: "Authorization: Bearer {key}", Plaintext: realKey, Last4: "xyz",
	})
	id, secret, token, err := keyfmt.Generate()
	if err != nil {
		t.Fatal(err)
	}
	st.PutKey(model.VirtualKey{
		ID: id, CredentialID: "cred_1", SecretHash: keyfmt.Hash(secret),
		Kind: model.KindStandard, Status: model.StatusActive,
	})
	prices, err := price.Load("")
	if err != nil {
		t.Fatal(err)
	}
	logs := &lockedBuf{}
	secrets := &redact.Secrets{}
	h := &harness{state: st, token: token, id: id, logs: logs}
	h.proxy = &proxy.Proxy{
		State: st, Clock: clock.System{}, Prices: prices,
		DefaultReservation: money.Dollar / 10, MaxBody: 1 << 20,
		Log:     slog.New(redact.New(slog.NewTextHandler(logs, nil), secrets)),
		Secrets: secrets,
	}
	return h
}

func (h *harness) do(t *testing.T, method, path, body string, hdr http.Header) *http.Response {
	t.Helper()
	srv := httptest.NewServer(h.proxy)
	t.Cleanup(srv.Close)
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, srv.URL+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+h.token)
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestStreamingFlushesBeforeUpstreamFinishes(t *testing.T) {
	first := make(chan struct{})
	release := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fl, _ := w.(http.Flusher)
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n")
		fl.Flush()
		close(first)
		<-release
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
		fl.Flush()
	}))
	defer up.Close()
	h := newHarness(t, up.URL, "openai", nil)
	srv := httptest.NewServer(h.proxy)
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/chat/completions", strings.NewReader(`{"model":"gpt-4o-mini","stream":true}`))
	req.Header.Set("Authorization", "Bearer "+h.token)
	resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	br := bufio.NewReader(resp.Body)
	got := make(chan string, 1)
	go func() {
		line, err := br.ReadString('\n')
		if err != nil {
			got <- err.Error()
			return
		}
		got <- line
	}()
	select {
	case line := <-got:
		if !strings.Contains(line, "hi") {
			t.Fatalf("first line %q", line)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the first stream chunk")
	}
	select {
	case <-first:
	default:
		t.Fatal("upstream had not produced the first chunk")
	}
	close(release)
}

func TestStripsClientAuthAndForwardingHeaders(t *testing.T) {
	seen := make(chan http.Header, 1)
	var gotQuery string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		seen <- r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer up.Close()
	h := newHarness(t, up.URL, "openai", nil)
	hdr := http.Header{}
	hdr.Set("X-Forwarded-For", "203.0.113.9")
	hdr.Set("X-Forwarded-Host", "evil.example")
	hdr.Set("Forwarded", "for=203.0.113.9")
	hdr.Set("X-Api-Key", "nope")
	hdr.Set("Accept-Encoding", "deflate")
	hdr.Set("Connection", "close, X-Trace")
	hdr.Set("X-Trace", "1")
	resp := h.do(t, http.MethodGet, "/v1/models?a=1&b=2;c", "", hdr)
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d %s", resp.StatusCode, b)
	}
	select {
	case got := <-seen:
		if got.Get("Authorization") != "Bearer "+realKey {
			t.Fatalf("auth %q", got.Get("Authorization"))
		}
		if strings.Contains(got.Get("Authorization"), h.token) || strings.Contains(strings.Join(got.Values("Authorization"), ","), "kmn_") {
			t.Fatal("virtual key was forwarded")
		}
		for _, name := range []string{"X-Forwarded-For", "X-Forwarded-Host", "Forwarded", "X-Api-Key", "X-Trace"} {
			if got.Get(name) != "" {
				t.Fatalf("%s was forwarded: %q", name, got.Get(name))
			}
		}
		if got.Get("Accept-Encoding") == "deflate" {
			t.Fatal("client Accept-Encoding was forwarded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream saw no request")
	}
	if gotQuery != "a=1&b=2;c" {
		t.Fatalf("query %q", gotQuery)
	}
	if strings.Contains(h.logs.String(), realKey) || strings.Contains(h.logs.String(), h.token) {
		t.Fatalf("logs leaked key material: %s", h.logs.String())
	}
}

func TestBlocksCrossHostRedirect(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models/relative" {
			w.Header().Set("Location", "/v1/models")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Location", "https://evil.example/steal")
		w.WriteHeader(http.StatusFound)
	}))
	defer up.Close()
	h := newHarness(t, up.URL, "openai", nil)
	resp := h.do(t, http.MethodGet, "/v1/models/x", "", nil)
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status %d %s", resp.StatusCode, b)
	}
	if resp.Header.Get("X-Keman-Error") != "upstream_redirect_blocked" {
		t.Fatalf("header %q body %s", resp.Header.Get("X-Keman-Error"), b)
	}
	if !strings.Contains(string(b), "keman_error") {
		t.Fatalf("body %s", b)
	}
	resp = h.do(t, http.MethodGet, "/v1/models/relative", "", nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("relative status %d", resp.StatusCode)
	}
	if resp.Header.Get("Location") != "/v1/models" {
		t.Fatalf("location %q", resp.Header.Get("Location"))
	}
}

func TestInjectsStreamUsage(t *testing.T) {
	var body []byte
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":4}}\n\n")
	}))
	defer up.Close()
	h := newHarness(t, up.URL, "openai", nil)
	resp := h.do(t, http.MethodPost, "/v1/chat/completions", `{"model":"gpt-4o-mini","stream":true}`, nil)
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	so, _ := got["stream_options"].(map[string]any)
	if so["include_usage"] != true {
		t.Fatalf("body %s", body)
	}
}

func TestCanaryLooksLikeUpstreamAuthFailure(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("canary must not call upstream")
	}))
	defer up.Close()
	h := newHarness(t, up.URL, "openai", nil)
	_, secret, token, err := keyfmt.Generate()
	if err != nil {
		t.Fatal(err)
	}
	h.state.PutKey(model.VirtualKey{
		ID: "canaryid", CredentialID: "cred_1", SecretHash: keyfmt.Hash(secret),
		Kind: model.KindCanary, Status: model.StatusRevoked,
	})
	// The generated id is random; the presented token must use that id.
	id, sec, full, err := keyfmt.Generate()
	if err != nil {
		t.Fatal(err)
	}
	_ = token
	h.state.PutKey(model.VirtualKey{
		ID: id, CredentialID: "cred_1", SecretHash: keyfmt.Hash(sec),
		Kind: model.KindCanary, Status: model.StatusRevoked,
	})
	h.token = full
	resp := h.do(t, http.MethodPost, "/v1/chat/completions", `{"model":"gpt-4o-mini"}`, nil)
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d %s", resp.StatusCode, b)
	}
	if resp.Header.Get("X-Keman-Error") != "" {
		t.Fatal("canary set X-Keman-Error")
	}
	if strings.Contains(string(b), "keman_error") || !strings.Contains(string(b), "invalid_api_key") {
		t.Fatalf("body %s", b)
	}
}

func TestInvalidKeyShape(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("invalid key reached upstream")
	}))
	defer up.Close()
	h := newHarness(t, up.URL, "openai", nil)
	h.token = "not-a-key"
	resp := h.do(t, http.MethodGet, "/v1/models", "", nil)
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("X-Keman-Error") != "invalid_key" {
		t.Fatalf("%d %s %s", resp.StatusCode, resp.Header.Get("X-Keman-Error"), b)
	}
}

func TestGenericPathAllowlist(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+realKey {
			t.Errorf("auth %s", r.Header.Get("Authorization"))
		}
		_, _ = io.WriteString(w, `{"id":"ch_1"}`)
	}))
	defer up.Close()
	h := newHarness(t, up.URL, "generic", []string{"POST /v1/charges"})
	resp := h.do(t, http.MethodPost, "/v1/charges", `{"amount":1}`, nil)
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	resp = h.do(t, http.MethodPost, "/v1/other", `{}`, nil)
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get("X-Keman-Error") != "path_not_allowed" {
		t.Fatalf("%d %s", resp.StatusCode, resp.Header.Get("X-Keman-Error"))
	}
}

func TestAnthropicStreamUsage(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+realKey {
			t.Errorf("auth %s", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":5,\"cache_read_input_tokens\":2}}}\n\n")
		_, _ = io.WriteString(w, "event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":7}}\n\n")
	}))
	defer up.Close()
	h := newHarness(t, up.URL, "anthropic", nil)
	resp := h.do(t, http.MethodPost, "/v1/messages", `{"model":"claude-haiku-4-5","max_tokens":8,"stream":true}`, nil)
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	if !strings.Contains(string(b), "message_delta") {
		t.Fatalf("body %s", b)
	}
}
