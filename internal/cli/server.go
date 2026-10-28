package cli

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kirank55/keman/internal/adminclient"
	"github.com/kirank55/keman/internal/app"
	"github.com/kirank55/keman/internal/config"
)

// startOwnedServer starts the local server when nothing is listening at base.
// stop is nil when a server is already up; the caller must not stop that one.
// The returned URL is the admin base the terminal UI should call.
func (c *cmd) startOwnedServer(ctx context.Context, base string, cfg config.Config) (string, func(), error) {
	if adminReachable(base) {
		return base, nil, nil
	}
	if !sameLocalAdmin(base, cfg.AdminListen) {
		return "", nil, fmt.Errorf("admin API is not reachable at %s", base)
	}
	master, err := readMaster(cfg, c.getenv)
	if err != nil {
		return "", nil, err
	}
	defer func() {
		for i := range master {
			master[i] = 0
		}
	}()
	logs, err := openServerLog(cfg.Database)
	if err != nil {
		logs = discardLog{}
	}
	owned, err := app.Open(ctx, cfg, master, app.WithLogWriter(logs))
	if err != nil {
		_ = logs.Close()
		return "", nil, err
	}
	if err := owned.Start(); err != nil {
		_ = owned.Close()
		_ = logs.Close()
		return "", nil, err
	}
	adminURL := base
	if _, ok := adminclient.UnixPath(base); !ok {
		adminURL = clientURL(owned.AdminURL())
	}
	return adminURL, func() {
		_ = owned.Close()
		_ = logs.Close()
	}, nil
}

func adminReachable(base string) bool {
	if path, ok := adminclient.UnixPath(base); ok {
		conn, err := net.DialTimeout("unix", path, 300*time.Millisecond)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	}
	host, err := urlHost(base)
	if err != nil {
		return false
	}
	conn, err := net.DialTimeout("tcp", host, 300*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// sameLocalAdmin reports whether base is the loopback client for listen.
func sameLocalAdmin(base, listen string) bool {
	if path, ok := adminclient.UnixPath(base); ok {
		return path == strings.TrimPrefix(listen, "unix://")
	}
	if strings.HasPrefix(listen, "unix://") || strings.HasPrefix(listen, "/") {
		return false
	}
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		return false
	}
	if !loopback(u.Hostname()) {
		return false
	}
	lhost, lport, err := net.SplitHostPort(listen)
	if err != nil || u.Port() != lport {
		return false
	}
	return loopback(lhost) || wildcard(lhost)
}

func clientURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	host := u.Hostname()
	if host == "" || host == "0.0.0.0" || host == "::" {
		u.Host = net.JoinHostPort("127.0.0.1", u.Port())
	}
	return u.String()
}

func urlHost(base string) (string, error) {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("admin URL %q", base)
	}
	return u.Host, nil
}

func loopback(host string) bool {
	return host == "127.0.0.1" || host == "localhost" || host == "::1"
}

func wildcard(host string) bool {
	return host == "" || host == "0.0.0.0" || host == "::" || host == "[::]"
}

func openServerLog(database string) (io.WriteCloser, error) {
	dir := filepath.Dir(database)
	if dir == "" {
		dir = "."
	}
	return os.OpenFile(filepath.Join(dir, "keman.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
}

type discardLog struct{}

func (discardLog) Write(p []byte) (int, error) { return len(p), nil }
func (discardLog) Close() error                { return nil }
