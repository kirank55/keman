// Package cli is the operator interface. After init, every mutation goes
// through the admin API so the running process stays in sync with SQLite.
package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/kirank55/keman/internal/adminclient"
	"github.com/kirank55/keman/internal/app"
	"github.com/kirank55/keman/internal/config"
	"github.com/kirank55/keman/internal/cryptoenc"
	"github.com/kirank55/keman/internal/expiry"
	"github.com/kirank55/keman/internal/money"
	"github.com/kirank55/keman/internal/tui"
)

// Version is the CLI version. The release workflow overrides it with -X.
var Version = "0.1.0-beta"

// Run executes one CLI invocation. It returns a process exit code.
func Run(ctx context.Context, args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	if stdin == nil {
		stdin = strings.NewReader("")
	}
	g := globals{configPath: "keman.yaml"}
	rest, err := g.parse(args)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 2
	}
	if g.adminToken == "" {
		g.adminToken = getenv("KEMAN_ADMIN_TOKEN")
	}
	if g.adminURL == "" {
		g.adminURL = getenv("KEMAN_ADMIN_URL")
	}
	c := &cmd{ctx: ctx, getenv: getenv, stdin: stdin, stdout: stdout, stderr: stderr, g: g}
	if len(rest) == 0 {
		return c.tui()
	}
	switch rest[0] {
	case "version":
		fmt.Fprintln(stdout, Version)
		return 0
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	case "init":
		return c.init(rest[1:])
	case "serve":
		return c.serve(rest[1:])
	case "admin-token":
		return c.adminToken(rest[1:])
	case "rekey":
		return c.rekey(rest[1:])
	case "upstream":
		return c.upstream(rest[1:])
	case "credential":
		return c.credential(rest[1:])
	case "key":
		return c.key(rest[1:])
	case "policy":
		return c.policy(rest[1:])
	case "alert":
		return c.alert(rest[1:])
	case "canary":
		return c.canary(rest[1:])
	case "exposure":
		return c.exposure(rest[1:])
	case "scan":
		return c.scan(rest[1:])
	case "detection":
		return c.detection(rest[1:])
	case "audit":
		return c.audit(rest[1:])
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", rest[0])
		usage(stderr)
		return 2
	}
}

type globals struct {
	configPath string
	adminURL   string
	adminToken string
}

func (g *globals) parse(args []string) ([]string, error) {
	var rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			rest = append(rest, args[i+1:]...)
			return rest, nil
		case a == "--config" || strings.HasPrefix(a, "--config="):
			v, ni, err := take(args, i)
			if err != nil {
				return nil, err
			}
			g.configPath = v
			i = ni
		case a == "--admin-url" || strings.HasPrefix(a, "--admin-url="):
			v, ni, err := take(args, i)
			if err != nil {
				return nil, err
			}
			g.adminURL = v
			i = ni
		case a == "--admin-token" || strings.HasPrefix(a, "--admin-token="):
			v, ni, err := take(args, i)
			if err != nil {
				return nil, err
			}
			g.adminToken = v
			i = ni
		default:
			rest = append(rest, a)
		}
	}
	return rest, nil
}

func take(args []string, i int) (string, int, error) {
	a := args[i]
	if v, ok := strings.CutPrefix(a, argName(a)+"="); ok && strings.Contains(a, "=") {
		return v, i, nil
	}
	name, _, _ := strings.Cut(strings.TrimPrefix(a, "--"), "=")
	if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
		return "", i, fmt.Errorf("missing value for --%s", name)
	}
	return args[i+1], i + 1, nil
}

func argName(a string) string {
	a = strings.TrimPrefix(a, "--")
	name, _, _ := strings.Cut(a, "=")
	return "--" + name
}

type cmd struct {
	ctx            context.Context
	getenv         func(string) string
	stdin          io.Reader
	stdout, stderr io.Writer
	g              globals
}

func (c *cmd) loadConfig() (config.Config, error) {
	return config.Load(c.g.configPath, c.getenv)
}

func (c *cmd) master() ([]byte, error) {
	cfg, err := c.loadConfig()
	if err != nil {
		return nil, err
	}
	return readMaster(cfg, c.getenv)
}

func readMaster(cfg config.Config, getenv func(string) string) ([]byte, error) {
	if v := strings.TrimSpace(getenv("KEMAN_MASTER_KEY")); v != "" {
		return cryptoenc.ParseMasterKey([]byte(v))
	}
	path := cfg.MasterKeyFile
	if path == "" {
		path = getenv("KEMAN_MASTER_KEY_FILE")
	}
	if path == "" {
		return nil, fmt.Errorf("set KEMAN_MASTER_KEY or master_key_file (a 32-byte key, or its base64/hex form)")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return cryptoenc.ParseMasterKey(b)
}

func (c *cmd) init(args []string) int {
	if len(args) != 0 {
		fmt.Fprintln(c.stderr, "init takes no arguments")
		return 2
	}
	cfg, err := c.loadConfig()
	if err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 1
	}
	if c.g.configPath != "" {
		if err := config.WriteIfAbsent(c.g.configPath, cfg); err != nil {
			fmt.Fprintln(c.stderr, err.Error())
			return 1
		}
	}
	master, noted, err := c.prepareMaster(cfg)
	if err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 1
	}
	if noted != "" {
		fmt.Fprintf(c.stderr, "master key file: %s\n", noted)
	}
	token, err := app.Init(c.ctx, cfg, master)
	if err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 1
	}
	fmt.Fprintf(c.stdout, "admin_token: %s\n", token)
	fmt.Fprintln(c.stdout, "store the admin token now; it is not shown again")
	next := "keman"
	if c.g.configPath != "" && c.g.configPath != "keman.yaml" {
		next += " --config " + c.g.configPath
	}
	fmt.Fprintf(c.stdout, "next: run %s and paste the token, or set KEMAN_ADMIN_TOKEN to skip the prompt\n", next)
	return 0
}

// prepareMaster returns the key init will use. When the config does not
// already name a master key file, the key is written to master.key beside
// the config and that path is recorded, so a later keman starts without
// KEMAN_MASTER_KEY. noted is the path just recorded.
func (c *cmd) prepareMaster(cfg config.Config) ([]byte, string, error) {
	master, keyErr := readMaster(cfg, c.getenv)
	if c.g.configPath == "" {
		if keyErr != nil {
			return nil, "", keyErr
		}
		return master, "", nil
	}
	disk, err := config.Load(c.g.configPath, func(string) string { return "" })
	if err != nil {
		return nil, "", err
	}
	if disk.MasterKeyFile != "" {
		if keyErr != nil {
			return nil, "", keyErr
		}
		return master, "", nil
	}
	ok, err := app.Initialized(c.ctx, cfg.Database)
	if err != nil {
		return nil, "", err
	}
	if keyErr != nil {
		if ok {
			return nil, "", fmt.Errorf("database is already initialized; set KEMAN_MASTER_KEY or master_key_file")
		}
		master = nil
	} else if ok {
		if err := app.CheckMaster(c.ctx, cfg, master); err != nil {
			return nil, "", err
		}
	}
	path := cfg.MasterKeyFile
	if path == "" {
		path = defaultMasterKeyPath(c.g.configPath)
	}
	master, err = ensureKeyFile(path, master)
	if err != nil {
		return nil, "", err
	}
	if err := config.SetMasterKeyFile(c.g.configPath, path); err != nil {
		return nil, "", err
	}
	return master, path, nil
}

func defaultMasterKeyPath(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), "master.key")
}

// ensureKeyFile returns the key stored at path. An existing file is kept.
// master is written when the file is missing; a nil master is generated.
func ensureKeyFile(path string, master []byte) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		got, err := cryptoenc.ParseMasterKey(bytes.TrimSpace(b))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if master != nil && !bytes.Equal(master, got) {
			return nil, fmt.Errorf("%s does not match KEMAN_MASTER_KEY", path)
		}
		return got, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	if master == nil {
		master, err = newMasterKey()
		if err != nil {
			return nil, err
		}
	}
	if err := writeKeyFile(path, master); err != nil {
		return nil, err
	}
	return append([]byte(nil), master...), nil
}

func newMasterKey() ([]byte, error) {
	b := make([]byte, cryptoenc.KeySize)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func writeKeyFile(path string, key []byte) error {
	body := base64.StdEncoding.EncodeToString(key) + "\n"
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.WriteString(body)
	cerr := f.Close()
	if werr != nil {
		_ = os.Remove(path)
		return werr
	}
	if cerr != nil {
		_ = os.Remove(path)
		return cerr
	}
	return os.Chmod(path, 0o600)
}

func (c *cmd) serve(args []string) int {
	if len(args) != 0 {
		fmt.Fprintln(c.stderr, "serve takes no arguments")
		return 2
	}
	cfg, err := c.loadConfig()
	if err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 1
	}
	master, err := readMaster(cfg, c.getenv)
	if err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 1
	}
	proc, err := app.Open(c.ctx, cfg, master)
	if err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 1
	}
	if err := proc.Start(); err != nil {
		_ = proc.Close()
		fmt.Fprintln(c.stderr, err.Error())
		return 1
	}
	ctx, stop := signal.NotifyContext(c.ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	if !config.AdminIsLocal(cfg) {
		fmt.Fprintln(c.stderr, "warning: admin_listen is not loopback or a Unix socket; the admin token is the only protection")
	}
	fmt.Fprintf(c.stdout, "proxy %s\nadmin %s\n", proc.ProxyURL(), proc.AdminURL())
	fmt.Fprintln(c.stderr, "press Ctrl+C to stop; CLI mutations need KEMAN_ADMIN_TOKEN")
	<-ctx.Done()
	if err := proc.Close(); err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 1
	}
	return 0
}

func (c *cmd) tui() int {
	if !tui.IsTerminal(c.stdout) {
		fmt.Fprintln(c.stderr, tui.ErrNotTerminal.Error())
		return 2
	}
	cfg, err := c.loadConfig()
	if err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 1
	}
	base := c.g.adminURL
	if base == "" {
		base = config.AdminURL(cfg)
	}
	// SIGTERM (or SIGINT outside raw mode) ends the UI normally, so a
	// server this process started still flushes spend on the way out.
	ctx, stopSignals := signal.NotifyContext(c.ctx, os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	base, stop, err := c.startOwnedServer(ctx, base, cfg)
	if err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 1
	}
	if stop != nil {
		defer stop()
	}
	api := adminclient.New(base, c.g.adminToken)
	if err := tui.Run(ctx, tui.NewHTTP(api), api.Base, c.stdin, c.stdout); err != nil {
		if errors.Is(err, tui.ErrNotTerminal) {
			fmt.Fprintln(c.stderr, err.Error())
			return 2
		}
		fmt.Fprintln(c.stderr, err.Error())
		return 1
	}
	return 0
}

func (c *cmd) api() (*client, error) {
	if c.g.adminToken == "" {
		return nil, fmt.Errorf("set --admin-token or KEMAN_ADMIN_TOKEN")
	}
	base := c.g.adminURL
	if base == "" {
		cfg, err := c.loadConfig()
		if err != nil {
			return nil, err
		}
		base = config.AdminURL(cfg)
	}
	return &client{adminclient.New(base, c.g.adminToken)}, nil
}

func (c *cmd) adminToken(args []string) int {
	if len(args) != 1 || args[0] != "rotate" {
		fmt.Fprintln(c.stderr, "usage: keman admin-token rotate")
		return 2
	}
	api, err := c.api()
	if err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 1
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := api.call(c.ctx, http.MethodPost, "/v1/admin-token/rotate", map[string]any{}, &out); err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 1
	}
	fmt.Fprintf(c.stdout, "admin_token: %s\n", out.Token)
	fmt.Fprintln(c.stderr, "store the admin token now; it is not shown again")
	return 0
}

func (c *cmd) rekey(args []string) int {
	f := newFlags(args)
	oldPath := f.str("old-master-key-file")
	newPath := f.str("new-master-key-file")
	if err := f.done(); err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 2
	}
	oldB, err := masterValue(oldPath, c.getenv("KEMAN_OLD_MASTER_KEY"))
	if err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 1
	}
	newB, err := masterValue(newPath, c.getenv("KEMAN_NEW_MASTER_KEY"))
	if err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 1
	}
	api, err := c.api()
	if err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 1
	}
	body := map[string]string{
		"old_master_key": base64.StdEncoding.EncodeToString(oldB),
		"new_master_key": base64.StdEncoding.EncodeToString(newB),
	}
	if err := api.call(c.ctx, http.MethodPost, "/v1/rekey", body, nil); err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 1
	}
	fmt.Fprintln(c.stdout, "rekey ok")
	fmt.Fprintln(c.stderr, "use the new master key before the next restart; the old one will not unwrap the data key")
	return 0
}

func masterValue(path, env string) ([]byte, error) {
	if strings.TrimSpace(env) != "" {
		return cryptoenc.ParseMasterKey([]byte(env))
	}
	if path == "" {
		return nil, fmt.Errorf("master key file or environment variable is required")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return cryptoenc.ParseMasterKey(b)
}

func (c *cmd) upstream(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.stderr, "usage: keman upstream add|list")
		return 2
	}
	api, err := c.api()
	if err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 1
	}
	switch args[0] {
	case "list":
		var out any
		if err := api.call(c.ctx, http.MethodGet, "/v1/upstreams", nil, &out); err != nil {
			fmt.Fprintln(c.stderr, err.Error())
			return 1
		}
		return c.printJSON(out)
	case "add":
		f := newFlags(args[1:])
		body := map[string]any{
			"name": f.str("name"), "profile": f.str("profile"), "host": f.str("host"),
			"protocol": "http", "path_allowlist": f.list("path"),
		}
		if p := f.str("port"); p != "" {
			n, err := strconv.Atoi(p)
			if err != nil {
				fmt.Fprintln(c.stderr, "port must be an integer")
				return 2
			}
			body["port"] = n
		}
		body["tls"] = f.bool("tls")
		body["insecure_skip_verify"] = f.bool("insecure")
		if sn := f.str("server-name"); sn != "" {
			body["server_name"] = sn
		}
		if f.bool("no-inject-usage") {
			body["inject_usage"] = false
		}
		if err := f.done(); err != nil {
			fmt.Fprintln(c.stderr, err.Error())
			return 2
		}
		if body["name"] == "" || body["profile"] == "" || body["host"] == "" || body["port"] == nil {
			fmt.Fprintln(c.stderr, "upstream add requires --name --profile --host --port")
			return 2
		}
		var out any
		if err := api.call(c.ctx, http.MethodPost, "/v1/upstreams", body, &out); err != nil {
			fmt.Fprintln(c.stderr, err.Error())
			return 1
		}
		return c.printJSON(out)
	default:
		fmt.Fprintln(c.stderr, "usage: keman upstream add|list")
		return 2
	}
}

func (c *cmd) credential(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.stderr, "usage: keman credential add|list|rotate")
		return 2
	}
	api, err := c.api()
	if err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 1
	}
	switch args[0] {
	case "list":
		var out any
		if err := api.call(c.ctx, http.MethodGet, "/v1/credentials", nil, &out); err != nil {
			fmt.Fprintln(c.stderr, err.Error())
			return 1
		}
		return c.printJSON(out)
	case "add":
		f := newFlags(args[1:])
		secret, err := c.secret(f)
		if err != nil {
			fmt.Fprintln(c.stderr, err.Error())
			return 1
		}
		up := f.str("upstream")
		body := map[string]any{
			"name": f.str("name"), "auth_style": f.str("auth"), "header_template": f.str("header"),
			"basic_username": f.str("username"), "secret_is_userpass": f.bool("userpass"), "secret": secret,
		}
		if err := f.done(); err != nil {
			fmt.Fprintln(c.stderr, err.Error())
			return 2
		}
		if body["name"] == "" {
			fmt.Fprintln(c.stderr, "credential add requires --name")
			return 2
		}
		id, err := c.resolveUpstream(api, up)
		if err != nil {
			fmt.Fprintln(c.stderr, err.Error())
			return 1
		}
		body["upstream_id"] = id
		if body["auth_style"] == "" {
			body["auth_style"] = "header"
		}
		if body["auth_style"] == "header" && body["header_template"] == "" {
			body["header_template"] = "Authorization: Bearer {key}"
		}
		var out any
		if err := api.call(c.ctx, http.MethodPost, "/v1/credentials", body, &out); err != nil {
			fmt.Fprintln(c.stderr, err.Error())
			return 1
		}
		return c.printJSON(out)
	case "rotate":
		if len(args) < 2 {
			fmt.Fprintln(c.stderr, "usage: keman credential rotate <id>")
			return 2
		}
		f := newFlags(args[2:])
		secret, err := c.secret(f)
		if err != nil {
			fmt.Fprintln(c.stderr, err.Error())
			return 1
		}
		if err := f.done(); err != nil {
			fmt.Fprintln(c.stderr, err.Error())
			return 2
		}
		id, err := c.resolveCredential(api, args[1])
		if err != nil {
			fmt.Fprintln(c.stderr, err.Error())
			return 1
		}
		var out any
		if err := api.call(c.ctx, http.MethodPost, "/v1/credentials/"+id+"/rotate", map[string]string{"secret": secret}, &out); err != nil {
			fmt.Fprintln(c.stderr, err.Error())
			return 1
		}
		return c.printJSON(out)
	default:
		fmt.Fprintln(c.stderr, "usage: keman credential add|list|rotate")
		return 2
	}
}

func (c *cmd) key(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.stderr, "usage: keman key create|list|rotate|expiry|disable|enable|revoke")
		return 2
	}
	api, err := c.api()
	if err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 1
	}
	switch args[0] {
	case "list":
		var out any
		if err := api.call(c.ctx, http.MethodGet, "/v1/keys", nil, &out); err != nil {
			fmt.Fprintln(c.stderr, err.Error())
			return 1
		}
		return c.printJSON(out)
	case "create":
		f := newFlags(args[1:])
		cred := f.str("credential")
		body := map[string]any{"name": f.str("name"), "kind": f.str("kind")}
		if f.bool("no-expiry") {
			body["no_expiry"] = true
		}
		if exp := f.str("expires"); exp != "" {
			at, err := expiry.Parse(exp, time.Now())
			if err != nil {
				fmt.Fprintln(c.stderr, "--expires: "+err.Error())
				return 2
			}
			if at == nil {
				body["no_expiry"] = true
			} else {
				body["expires_at"] = at.Format(time.RFC3339)
			}
		}
		if err := f.done(); err != nil {
			fmt.Fprintln(c.stderr, err.Error())
			return 2
		}
		if body["name"] == "" {
			fmt.Fprintln(c.stderr, "key create requires --name")
			return 2
		}
		id, err := c.resolveCredential(api, cred)
		if err != nil {
			fmt.Fprintln(c.stderr, err.Error())
			return 1
		}
		body["credential_id"] = id
		var out map[string]any
		if err := api.call(c.ctx, http.MethodPost, "/v1/keys", body, &out); err != nil {
			fmt.Fprintln(c.stderr, err.Error())
			return 1
		}
		fmt.Fprintln(c.stderr, "store the virtual key (token) now; it is not shown again")
		if out["expires_at"] == nil && out["kind"] != "canary" {
			fmt.Fprintln(c.stderr, "warning: this key never expires; a copy that leaks keeps working until you revoke it")
		}
		return c.printJSON(out)
	case "rotate":
		return c.keyRotate(api, args[1:])
	case "expiry":
		return c.keyExpiry(api, args[1:])
	case "disable", "enable", "revoke":
		if len(args) < 2 {
			fmt.Fprintf(c.stderr, "usage: keman key %s <id-or-name>\n", args[0])
			return 2
		}
		id, err := c.resolveKey(api, args[1])
		if err != nil {
			fmt.Fprintln(c.stderr, err.Error())
			return 1
		}
		var out any
		if err := api.call(c.ctx, http.MethodPost, "/v1/keys/"+id+"/"+args[0], map[string]any{}, &out); err != nil {
			fmt.Fprintln(c.stderr, err.Error())
			return 1
		}
		return c.printJSON(out)
	default:
		fmt.Fprintln(c.stderr, "usage: keman key create|list|rotate|expiry|disable|enable|revoke")
		return 2
	}
}

func (c *cmd) policy(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.stderr, "usage: keman policy set|dry-run")
		return 2
	}
	api, err := c.api()
	if err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 1
	}
	switch args[0] {
	case "dry-run":
		if len(args) < 2 {
			fmt.Fprintln(c.stderr, "usage: keman policy dry-run <key>")
			return 2
		}
		id, err := c.resolveKey(api, args[1])
		if err != nil {
			fmt.Fprintln(c.stderr, err.Error())
			return 1
		}
		var out any
		if err := api.call(c.ctx, http.MethodGet, "/v1/keys/"+id+"/dry-run", nil, &out); err != nil {
			fmt.Fprintln(c.stderr, err.Error())
			return 1
		}
		return c.printJSON(out)
	case "set":
		if len(args) < 2 {
			fmt.Fprintln(c.stderr, "usage: keman policy set <key> [flags]")
			return 2
		}
		f := newFlags(args[2:])
		mode := f.str("mode")
		rpm := f.str("rpm")
		daily := f.str("daily-usd")
		monthly := f.str("monthly-usd")
		paths := f.list("path")
		models := f.list("model")
		cidrs := f.list("cidr")
		countries := f.list("country")
		yes := f.bool("yes")
		if err := f.done(); err != nil {
			fmt.Fprintln(c.stderr, err.Error())
			return 2
		}
		keyID, err := c.resolveKey(api, args[1])
		if err != nil {
			fmt.Fprintln(c.stderr, err.Error())
			return 1
		}
		cur, err := c.keyPolicy(api, keyID)
		if err != nil {
			fmt.Fprintln(c.stderr, err.Error())
			return 1
		}
		if mode != "" {
			cur.Mode = mode
		}
		if cur.Mode == "" {
			cur.Mode = "alert_only"
		}
		if rpm != "" {
			n, err := strconv.Atoi(rpm)
			if err != nil {
				fmt.Fprintln(c.stderr, "rpm must be an integer")
				return 2
			}
			cur.RPM = &n
		}
		if daily != "" {
			micro, err := money.ParseUSD(daily)
			if err != nil {
				fmt.Fprintln(c.stderr, err.Error())
				return 2
			}
			cur.DailyCapMicro = &micro
		}
		if monthly != "" {
			micro, err := money.ParseUSD(monthly)
			if err != nil {
				fmt.Fprintln(c.stderr, err.Error())
				return 2
			}
			cur.MonthlyCapMicro = &micro
		}
		if len(paths) > 0 {
			cur.Paths = paths
		}
		if len(models) > 0 {
			cur.Models = models
		}
		if len(cidrs) > 0 {
			cur.CIDRs = cidrs
		}
		if len(countries) > 0 {
			cur.Countries = countries
		}
		cur.Confirm = yes
		var out any
		if err := api.call(c.ctx, http.MethodPut, "/v1/keys/"+keyID+"/policy", cur, &out); err != nil {
			fmt.Fprintln(c.stderr, err.Error())
			return 1
		}
		return c.printJSON(out)
	default:
		fmt.Fprintln(c.stderr, "usage: keman policy set|dry-run")
		return 2
	}
}

type policyBody struct {
	Mode            string   `json:"mode"`
	RPM             *int     `json:"rpm,omitempty"`
	DailyCapMicro   *int64   `json:"daily_cap_microusd,omitempty"`
	MonthlyCapMicro *int64   `json:"monthly_cap_microusd,omitempty"`
	Paths           []string `json:"paths,omitempty"`
	Models          []string `json:"models,omitempty"`
	CIDRs           []string `json:"cidrs,omitempty"`
	Countries       []string `json:"countries,omitempty"`
	Confirm         bool     `json:"confirm,omitempty"`
}

func (c *cmd) keyPolicy(api *client, id string) (policyBody, error) {
	var keys []struct {
		ID     string `json:"id"`
		Policy *struct {
			Mode            string   `json:"mode"`
			RPM             *int     `json:"rpm"`
			DailyCapMicro   *int64   `json:"daily_cap_microusd"`
			MonthlyCapMicro *int64   `json:"monthly_cap_microusd"`
			Paths           []string `json:"paths"`
			Models          []string `json:"models"`
			CIDRs           []string `json:"cidrs"`
			Countries       []string `json:"countries"`
		} `json:"policy"`
	}
	if err := api.call(c.ctx, http.MethodGet, "/v1/keys", nil, &keys); err != nil {
		return policyBody{}, err
	}
	for _, k := range keys {
		if k.ID != id {
			continue
		}
		if k.Policy == nil {
			return policyBody{}, nil
		}
		return policyBody{
			Mode: k.Policy.Mode, RPM: k.Policy.RPM, DailyCapMicro: k.Policy.DailyCapMicro,
			MonthlyCapMicro: k.Policy.MonthlyCapMicro, Paths: k.Policy.Paths, Models: k.Policy.Models,
			CIDRs: k.Policy.CIDRs, Countries: k.Policy.Countries,
		}, nil
	}
	return policyBody{}, fmt.Errorf("virtual key %s not found", id)
}

func (c *cmd) alert(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.stderr, "usage: keman alert add|list")
		return 2
	}
	api, err := c.api()
	if err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 1
	}
	switch args[0] {
	case "list":
		var out any
		if err := api.call(c.ctx, http.MethodGet, "/v1/alerts", nil, &out); err != nil {
			fmt.Fprintln(c.stderr, err.Error())
			return 1
		}
		return c.printJSON(out)
	case "add":
		f := newFlags(args[1:])
		kind := f.str("kind")
		url := f.str("url")
		secret, err := c.secret(f)
		if err != nil && kind == "webhook" {
			fmt.Fprintln(c.stderr, err.Error())
			return 1
		}
		if err := f.done(); err != nil {
			fmt.Fprintln(c.stderr, err.Error())
			return 2
		}
		if kind == "" || url == "" {
			fmt.Fprintln(c.stderr, "alert add requires --kind and --url")
			return 2
		}
		var out any
		body := map[string]string{"kind": kind, "url": url, "secret": secret}
		if err := api.call(c.ctx, http.MethodPost, "/v1/alerts", body, &out); err != nil {
			fmt.Fprintln(c.stderr, err.Error())
			return 1
		}
		return c.printJSON(out)
	default:
		fmt.Fprintln(c.stderr, "usage: keman alert add|list")
		return 2
	}
}

func (c *cmd) audit(args []string) int {
	if len(args) == 0 || args[0] != "list" {
		fmt.Fprintln(c.stderr, "usage: keman audit list")
		return 2
	}
	api, err := c.api()
	if err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 1
	}
	var out any
	if err := api.call(c.ctx, http.MethodGet, "/v1/audit", nil, &out); err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 1
	}
	return c.printJSON(out)
}

func (c *cmd) secret(f *flagSet) (string, error) {
	if env := f.str("secret-env"); env != "" {
		v := c.getenv(env)
		if v == "" {
			return "", fmt.Errorf("environment variable %s is empty", env)
		}
		return v, nil
	}
	if path := f.str("secret-file"); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
	if s := f.str("secret"); s != "" {
		fmt.Fprintln(c.stderr, "warning: --secret puts the key in the process list; prefer --secret-env or --secret-file")
		return s, nil
	}
	return "", fmt.Errorf("set --secret-env or --secret-file")
}

func (c *cmd) resolveUpstream(api *client, nameOrID string) (string, error) {
	if nameOrID == "" {
		return "", fmt.Errorf("--upstream is required")
	}
	var list []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := api.call(c.ctx, http.MethodGet, "/v1/upstreams", nil, &list); err != nil {
		return "", err
	}
	for _, u := range list {
		if u.ID == nameOrID || u.Name == nameOrID {
			return u.ID, nil
		}
	}
	return "", fmt.Errorf("upstream %s not found", nameOrID)
}

func (c *cmd) resolveKey(api *client, nameOrID string) (string, error) {
	if nameOrID == "" {
		return "", fmt.Errorf("virtual key id or name is required")
	}
	var list []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := api.call(c.ctx, http.MethodGet, "/v1/keys", nil, &list); err != nil {
		return "", err
	}
	var names []string
	for _, k := range list {
		if k.ID == nameOrID {
			return k.ID, nil
		}
		if k.Name == nameOrID {
			names = append(names, k.ID)
		}
	}
	if len(names) == 1 {
		return names[0], nil
	}
	if len(names) > 1 {
		return "", fmt.Errorf("virtual key name %s is ambiguous; use the id", nameOrID)
	}
	return "", fmt.Errorf("virtual key %s not found", nameOrID)
}

func (c *cmd) resolveCredential(api *client, nameOrID string) (string, error) {
	if nameOrID == "" {
		return "", fmt.Errorf("--credential is required")
	}
	var list []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := api.call(c.ctx, http.MethodGet, "/v1/credentials", nil, &list); err != nil {
		return "", err
	}
	for _, u := range list {
		if u.ID == nameOrID || u.Name == nameOrID {
			return u.ID, nil
		}
	}
	return "", fmt.Errorf("credential %s not found", nameOrID)
}

func (c *cmd) printJSON(v any) int {
	enc := json.NewEncoder(c.stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 1
	}
	return 0
}

// client is the admin API client with CLI-friendly error text.
type client struct{ *adminclient.Client }

func (c *client) call(ctx context.Context, method, path string, in any, out any) error {
	err := c.Call(ctx, method, path, in, out)
	var apiErr *adminclient.APIError
	if errors.As(err, &apiErr) {
		return formatAPIError(apiErr.Status, apiErr.Body)
	}
	return err
}

type flagSet struct {
	args  []string
	seen  map[string][]string
	bools map[string]bool
	err   error
}

func newFlags(args []string) *flagSet {
	f := &flagSet{seen: map[string][]string{}, bools: map[string]bool{}}
	boolNames := map[string]bool{
		"tls": true, "insecure": true, "no-inject-usage": true, "userpass": true, "yes": true,
		"no-expiry": true, "strict": true, "history": true, "json": true,
		"learned": true, "expect-disable": true, "list": true, "live": true,
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			f.args = append(f.args, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(a, "--") {
			f.args = append(f.args, a)
			continue
		}
		name := strings.TrimPrefix(a, "--")
		val := ""
		if n, v, ok := strings.Cut(name, "="); ok {
			name, val = n, v
		}
		if boolNames[name] && !strings.Contains(a, "=") {
			f.bools[name] = true
			continue
		}
		if val == "" {
			if i+1 >= len(args) {
				f.err = fmt.Errorf("missing value for --%s", name)
				return f
			}
			i++
			val = args[i]
		}
		f.seen[name] = append(f.seen[name], val)
	}
	return f
}

func (f *flagSet) str(name string) string {
	v := f.seen[name]
	if len(v) == 0 {
		return ""
	}
	return v[len(v)-1]
}

func (f *flagSet) list(name string) []string { return append([]string(nil), f.seen[name]...) }

func (f *flagSet) bool(name string) bool { return f.bools[name] }

func (f *flagSet) done() error {
	if f.err != nil {
		return f.err
	}
	if len(f.args) > 0 {
		return fmt.Errorf("unexpected argument %q", f.args[0])
	}
	return nil
}

func formatAPIError(status int, raw []byte) error {
	var ae struct {
		Error struct {
			Type    string `json:"type"`
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
		DryRun json.RawMessage `json:"dry_run"`
	}
	if json.Unmarshal(raw, &ae) == nil && ae.Error.Message != "" {
		msg := ae.Error.Message
		if ae.Error.Code != "" {
			msg = ae.Error.Code + ": " + msg
		}
		if len(bytes.TrimSpace(ae.DryRun)) > 0 && string(ae.DryRun) != "null" {
			var buf bytes.Buffer
			if json.Indent(&buf, ae.DryRun, "", "  ") == nil {
				msg += "\n" + buf.String()
			}
			if ae.Error.Code == "confirm_required" {
				msg += "\nre-run with --yes to confirm"
			}
		}
		return fmt.Errorf("%s", msg)
	}
	text := strings.TrimSpace(string(raw))
	if text == "" {
		return fmt.Errorf("admin API returned HTTP %d", status)
	}
	return fmt.Errorf("%s", text)
}

func usage(w io.Writer) {
	fmt.Fprint(w, `keman `+Version+` — self-hosted proxy that keeps real API keys out of your apps

Apps get virtual keys instead. A virtual key can be locked to your network, expires, raises alerts
when it is misused, and is revoked without touching the real key.

With no command, keman opens the full-screen UI. It needs a terminal and an initialized database. It starts the local server when nothing is listening, and stops that server on exit. init writes master.key and records master_key_file. Type the admin token at startup, or set KEMAN_ADMIN_TOKEN.

Find and contain leaks
  keman scan [path ...] [--history] [--json]   real API keys in files and git history (exit 3 if any)
  keman exposure [--strict]                    keys that are easy to abuse if leaked (--strict: exit 3)
  keman canary create --credential primary --name decoy --base-url https://keman.example.com
  keman key rotate <id-or-name> [--grace 24h]  new key now; the old one stops after the grace (0 revokes)
  keman key revoke <id-or-name>
  keman detection list [--key id]
  keman detection test [--scenario name] [--json]
  keman detection test --file events.jsonl [--learned] [--expect rule,rule] [--expect-disable]
  keman detection test --live --secret-file virtual.key [--proxy URL]

Set up
  keman init
  keman serve
  keman upstream add --name openai --profile openai --host api.openai.com --port 443 --tls
  keman upstream add --name stripe --profile generic --host api.stripe.com --port 443 --tls --path "POST /v1/charges"
  keman upstream list
  keman credential add --upstream openai --name primary --header "Authorization: Bearer {key}" --secret-file ./secret
  keman credential list
  keman credential rotate <id-or-name> --secret-env OPENAI_API_KEY
  keman alert add --kind webhook --url https://example --secret-file ./hook
  keman alert list

Virtual keys
  keman key create --credential primary --name laptop             expires after default_key_ttl (90 days)
  keman key create --credential primary --name ci --expires 30d   or 2026-12-31, RFC3339, or never
  keman key create --credential primary --name decoy --kind canary
  keman key expiry <id-or-name> <30d|2026-12-31|RFC3339|never>
  keman key list
  keman key disable|enable <id-or-name>
  keman policy set <id-or-name> --cidr 203.0.113.0/24 --country US --rpm 60
  keman policy set <id-or-name> --daily-usd 1.50 --monthly-usd 20    LLM upstreams only
  keman policy set <id-or-name> --mode auto_disable --yes
  keman policy dry-run <id-or-name>
  keman audit list

Admin
  keman admin-token rotate
  keman rekey --old-master-key-file old --new-master-key-file new
  keman version

Global flags (before or after the command): --config PATH --admin-url URL --admin-token TOKEN
  KEMAN_ADMIN_TOKEN, KEMAN_ADMIN_URL, KEMAN_MASTER_KEY, KEMAN_DATABASE override the same settings.
  --admin-url defaults to admin_listen in --config (unix:// sockets are supported).
Secrets belong in --secret-env or --secret-file, not in the command line.
Official OpenAI SDKs need base_url http://127.0.0.1:8080/v1 (note the /v1). Anthropic SDKs use http://127.0.0.1:8080.
`)
}
