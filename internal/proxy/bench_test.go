package proxy_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestProxyOverheadDistribution(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer up.Close()
	direct := sample(t, up.URL+"/v1/chat/completions", "")
	h := newHarness(t, up.URL, "openai", nil)
	srv := httptest.NewServer(h.proxy)
	defer srv.Close()
	via := sample(t, srv.URL+"/v1/chat/completions", h.token)
	d50, d99 := pct(direct)
	p50, p99 := pct(via)
	t.Logf("direct p50=%s p99=%s proxy p50=%s p99=%s overhead p50=%s p99=%s",
		d50, d99, p50, p99, p50-d50, p99-d99)
}

func sample(t *testing.T, url, token string) []time.Duration {
	t.Helper()
	client := &http.Client{}
	body := `{"model":"gpt-4o-mini"}`
	out := make([]time.Duration, 0, 200)
	for i := 0; i < 200; i++ {
		req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		out = append(out, time.Since(start))
		if resp.StatusCode != 200 {
			t.Fatalf("status %d", resp.StatusCode)
		}
	}
	return out
}

func pct(ds []time.Duration) (time.Duration, time.Duration) {
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	return ds[len(ds)/2], ds[len(ds)*99/100]
}

func BenchmarkProxyOverhead(b *testing.B) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer up.Close()
	h := newHarness(b, up.URL, "openai", nil)
	srv := httptest.NewServer(h.proxy)
	defer srv.Close()
	client := &http.Client{}
	body := `{"model":"gpt-4o-mini"}`
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/chat/completions", strings.NewReader(body))
		if err != nil {
			b.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+h.token)
		resp, err := client.Do(req)
		if err != nil {
			b.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			b.Fatalf("status %d", resp.StatusCode)
		}
	}
}
