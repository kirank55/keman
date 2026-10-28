package cli

import (
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kirank55/keman/internal/app"
	"github.com/kirank55/keman/internal/config"
)

func TestSameLocalAdmin(t *testing.T) {
	cases := []struct {
		base, listen string
		want         bool
	}{
		{"http://127.0.0.1:8081", "127.0.0.1:8081", true},
		{"http://localhost:8081", "127.0.0.1:8081", true},
		{"http://127.0.0.1:8081", "0.0.0.0:8081", true},
		{"http://127.0.0.1:8081", ":8081", true},
		{"http://127.0.0.1:9090", "127.0.0.1:8081", false},
		{"http://example.invalid:8081", "127.0.0.1:8081", false},
		{"http://127.0.0.1:8081", "/tmp/keman.sock", false},
	}
	for _, tc := range cases {
		if got := sameLocalAdmin(tc.base, tc.listen); got != tc.want {
			t.Errorf("sameLocalAdmin(%s, %s) = %v", tc.base, tc.listen, got)
		}
	}
}

func TestStartOwnedServerAttaches(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	base := "http://" + ln.Addr().String()
	c := &cmd{ctx: context.Background(), getenv: func(string) string { return "" }}
	got, stop, err := c.startOwnedServer(c.ctx, base, config.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	if stop != nil || got != base {
		t.Fatalf("stop %v base %s", stop != nil, got)
	}
}

func TestStartOwnedServerRefusesRemote(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	c := &cmd{ctx: context.Background(), getenv: func(string) string { return "" }}
	cfg := config.Defaults()
	_, _, err = c.startOwnedServer(c.ctx, "http://"+addr, cfg)
	if err == nil || !strings.Contains(err.Error(), "not reachable") {
		t.Fatal(err)
	}
}

func TestStartOwnedServerStops(t *testing.T) {
	dir := t.TempDir()
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = 9
	}
	cfg := config.Defaults()
	cfg.Database = filepath.Join(dir, "keman.db")
	if _, err := app.Init(context.Background(), cfg, raw); err != nil {
		t.Fatal(err)
	}
	adminLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	adminAddr := adminLn.Addr().String()
	adminLn.Close()
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyAddr := proxyLn.Addr().String()
	proxyLn.Close()
	cfg.AdminListen = adminAddr
	cfg.ProxyListen = proxyAddr

	key := base64.StdEncoding.EncodeToString(raw)
	c := &cmd{
		ctx: context.Background(),
		getenv: func(k string) string {
			if k == "KEMAN_MASTER_KEY" {
				return key
			}
			return ""
		},
		stderr: io.Discard,
	}
	base := "http://" + adminAddr
	got, stop, err := c.startOwnedServer(c.ctx, base, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if stop == nil {
		t.Fatal("expected to own the server")
	}
	defer func() {
		if stop != nil {
			stop()
		}
	}()
	if got != base {
		t.Fatalf("admin url %s", got)
	}

	var resp *http.Response
	for i := 0; i < 25; i++ {
		resp, err = http.Get(got + "/v1/keys")
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d", resp.StatusCode)
	}

	stop()
	stop = nil
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !adminReachable(got) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("server still listening")
}
