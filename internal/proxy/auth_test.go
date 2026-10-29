package proxy_test

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kirank55/keman/internal/model"
	"github.com/kirank55/keman/internal/state"
)

// send is h.do without the default Bearer header.
func send(t *testing.T, h *harness, method, path, body string, hdr http.Header) *http.Response {
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
	req.Header = hdr
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func basic(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func TestKeyFromClientAuthFormats(t *testing.T) {
	seen := make(chan http.Header, 1)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Clone()
	}))
	defer up.Close()
	h := newHarness(t, up.URL, "openai", nil)
	cases := map[string]http.Header{
		"bearer":          {"Authorization": {"Bearer " + h.token}},
		"github token":    {"Authorization": {"token " + h.token}},
		"bare":            {"Authorization": {h.token}},
		"basic password":  {"Authorization": {basic("AC0123456789", h.token)}},
		"basic username":  {"Authorization": {basic(h.token, "")}},
		"x-api-key":       {"X-Api-Key": {h.token}},
		"provider header": {"X-Postmark-Server-Token": {h.token}},
		"bearer in other": {"X-Goog-Api-Key": {"Bearer " + h.token}},
	}
	for name, hdr := range cases {
		resp := send(t, h, http.MethodGet, "/v1/models", "", hdr)
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("%s: %d %s", name, resp.StatusCode, b)
		}
		got := <-seen
		if got.Get("Authorization") != "Bearer "+realKey {
			t.Fatalf("%s: auth %q", name, got.Get("Authorization"))
		}
		for k, vs := range got {
			for _, v := range vs {
				if strings.Contains(v, h.token) {
					t.Fatalf("%s: virtual key forwarded in %s", name, k)
				}
			}
		}
	}
}

func TestBasicWithoutVirtualKeyIsRejected(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("reached upstream")
	}))
	defer up.Close()
	h := newHarness(t, up.URL, "openai", nil)
	for _, v := range []string{basic("AC0123456789", "real-token"), "Basic !!!", "token nope"} {
		resp := send(t, h, http.MethodGet, "/v1/models", "", http.Header{"Authorization": {v}})
		if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("X-Keman-Error") != "invalid_key" {
			t.Fatalf("%q: %d %s", v, resp.StatusCode, resp.Header.Get("X-Keman-Error"))
		}
	}
}

// A key sent in the header the credential itself uses is replaced there.
func TestProviderHeaderGetsTheRealKey(t *testing.T) {
	seen := make(chan http.Header, 1)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Clone()
	}))
	defer up.Close()
	h := newHarness(t, up.URL, "generic", []string{"POST /email"})
	cred, _ := h.state.Credential("cred_1")
	cred.HeaderTemplate = "X-Postmark-Server-Token: {key}"
	h.state.PutCredential(cred)
	resp := send(t, h, http.MethodPost, "/email", `{}`, http.Header{"X-Postmark-Server-Token": {h.token}})
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	got := <-seen
	if v := got.Values("X-Postmark-Server-Token"); len(v) != 1 || v[0] != realKey {
		t.Fatalf("token header %q", v)
	}
	if got.Get("Authorization") != "" {
		t.Fatalf("unexpected Authorization %q", got.Get("Authorization"))
	}
}

func TestPresetPricesApplyToCappedKeys(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"usage":{"prompt_tokens":10,"completion_tokens":5}}`)
	}))
	defer up.Close()
	h := newHarness(t, up.URL, "openai", []string{"POST /openai/v1/chat/completions"})
	capMicro := int64(1_000_000)
	pol, err := state.ParsePolicy(model.Policy{KeyID: h.id, DailyCapMicro: &capMicro, Mode: model.ModeAlertOnly})
	if err != nil {
		t.Fatal(err)
	}
	h.state.PutPolicy(pol)
	body := `{"model":"openai/gpt-oss-120b","max_tokens":10}`

	resp := h.do(t, http.MethodPost, "/openai/v1/chat/completions", body, nil)
	if resp.Header.Get("X-Keman-Error") != "unknown_model_price" {
		t.Fatalf("without a preset: %d %s", resp.StatusCode, resp.Header.Get("X-Keman-Error"))
	}

	cur, _ := h.state.Upstream("up_1")
	cur.Preset = "groq"
	h.state.PutUpstream(cur)
	resp = h.do(t, http.MethodPost, "/openai/v1/chat/completions", body, nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("with the groq preset: %d %s", resp.StatusCode, b)
	}
}
