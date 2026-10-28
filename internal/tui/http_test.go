package tui

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/kirank55/keman/internal/adminclient"
)

func TestHTTPMapsKeySpend(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/keys" {
			t.Errorf("path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id":"k","name":"laptop","kind":"standard","status":"active","spend_today_microusd":420000,"spend_month_microusd":4200000,"spend_open_microusd":100000,"policy":{"mode":"alert_only","daily_cap_microusd":1500000}}]`))
	}))
	defer srv.Close()
	keys, err := NewHTTP(adminclient.New(srv.URL, "kma")).ListKeys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].SpendToday != 420000 || keys[0].SpendOpen != 100000 {
		t.Fatalf("%+v", keys)
	}
	if keys[0].Policy == nil || keys[0].Policy.DailyCapMicro == nil || *keys[0].Policy.DailyCapMicro != 1_500_000 {
		t.Fatalf("%+v", keys[0].Policy)
	}
}

func TestHTTPConfirmRequired(t *testing.T) {
	body := `{"error":{"type":"keman_error","code":"confirm_required","message":"Switching to auto_disable needs confirmation. Review the dry-run report."},"dry_run":{"would_disable":true,"detections":4,"requests_would_block":9}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	_, err := NewHTTP(adminclient.New(srv.URL, "kma")).PutPolicy(context.Background(), "k", Policy{Mode: "auto_disable"}, false)
	var conf *ConfirmError
	if !errors.As(err, &conf) {
		t.Fatalf("%T %v", err, err)
	}
	if !conf.Report.WouldDisable || conf.Report.Detections != 4 || conf.Report.RequestsWouldBlock != 9 {
		t.Fatalf("%+v", conf.Report)
	}
}

func TestHTTPKeyUsage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/keys/abcd/usage" {
			t.Errorf("path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"requests":2,"tokens_in":30,"tokens_out":10,"cost_microusd":1500,"priced":1,"last_seen":"2026-10-27T16:58:00Z","clients":[{"ip":"127.0.0.1","requests":2,"last_seen":"2026-10-27T16:58:00Z"}],"models":[{"model":"openai/gpt-4o-mini","requests":2,"tokens_in":30,"tokens_out":10,"cost_microusd":1500,"priced":1}],"recent":[{"time":"2026-10-27T16:58:00Z","ip":"127.0.0.1","operation":"POST /api/v1/chat/completions","status":200,"latency_ms":1885,"model":"openai/gpt-4o-mini","tokens_in":10,"tokens_out":4,"cost_microusd":1500}]}`))
	}))
	defer srv.Close()
	got, err := NewHTTP(adminclient.New(srv.URL, "kma")).KeyUsage(context.Background(), "abcd")
	if err != nil {
		t.Fatal(err)
	}
	if got.Requests != 2 || got.TokensIn != 30 || len(got.Clients) != 1 || got.Clients[0].IP != "127.0.0.1" {
		t.Fatalf("%+v", got)
	}
	if len(got.Recent) != 1 || got.Recent[0].Operation != "POST /api/v1/chat/completions" || got.Recent[0].CostMicro == nil {
		t.Fatalf("%+v", got.Recent)
	}
}

func TestHTTPAddUpstreamAndCredential(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = append(got, r.Method+" "+r.URL.Path+" "+string(b))
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/upstreams":
			_, _ = w.Write([]byte(`{"id":"u1","name":"openrouter","profile":"openai","host":"openrouter.ai","port":443,"tls":true}`))
		case "/v1/credentials":
			_, _ = w.Write([]byte(`{"id":"c1","upstream_id":"u1","name":"primary","auth_style":"header","last4":"cret"}`))
		default:
			t.Errorf("path %s", r.URL.Path)
		}
	}))
	defer srv.Close()
	h := NewHTTP(adminclient.New(srv.URL, "kma"))
	up, err := h.AddUpstream(context.Background(), UpstreamDraft{
		Name: "openrouter", Profile: "openai", Host: "openrouter.ai", Port: 443, TLS: true,
		Paths: []string{"POST /api/v1/chat/completions"},
	})
	if err != nil || up.ID != "u1" || up.Host != "openrouter.ai" || !up.TLS {
		t.Fatal(err, up)
	}
	cred, err := h.AddCredential(context.Background(), CredentialDraft{UpstreamID: "u1", Name: "primary", Secret: "sk-test"})
	if err != nil || cred.ID != "c1" || cred.Last4 != "cret" || cred.UpstreamID != "u1" {
		t.Fatal(err, cred)
	}
	blob := strings.Join(got, "\n")
	if !strings.Contains(blob, `"path_allowlist":["POST /api/v1/chat/completions"]`) {
		t.Fatal(blob)
	}
	if !strings.Contains(blob, `"secret":"sk-test"`) || !strings.Contains(blob, `"header_template":"Authorization: Bearer {key}"`) {
		t.Fatal(blob)
	}
}

func TestExplainUnauthorized(t *testing.T) {
	err := explain(&adminclient.APIError{Status: http.StatusUnauthorized, Message: "The admin token is invalid."}, "http://127.0.0.1:8081")
	if !unauthorized(err) || err.Error() != "The admin token is invalid." {
		t.Fatal(err)
	}
}

func TestExplainDial(t *testing.T) {
	err := explain(&url.Error{Op: "Get", URL: "http://127.0.0.1:8081", Err: errors.New("connection refused")}, "http://127.0.0.1:8081")
	if !strings.Contains(err.Error(), "not reachable") {
		t.Fatal(err)
	}
}
