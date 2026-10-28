package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kirank55/keman/internal/app"
	"github.com/kirank55/keman/internal/config"
	"github.com/kirank55/keman/internal/cryptoenc"
)

func TestInitWritesMasterKey(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "keman.yaml")
	dbPath := filepath.Join(dir, "keman.db")
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"--config", cfgPath, "init"}, func(k string) string {
		if k == "KEMAN_DATABASE" {
			return dbPath
		}
		return ""
	}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code %d\n%s\n%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "admin_token: kma_") {
		t.Fatal(stdout.String())
	}
	keyPath := filepath.Join(dir, "master.key")
	if !strings.Contains(stderr.String(), "master key file: "+keyPath) {
		t.Fatal(stderr.String())
	}
	body, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout.String(), strings.TrimSpace(string(body))) || strings.Contains(stderr.String(), strings.TrimSpace(string(body))) {
		t.Fatal("init printed the master key")
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", info.Mode().Perm())
	}
	cfg, err := config.Load(cfgPath, func(k string) string {
		if k == "KEMAN_DATABASE" {
			return dbPath
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MasterKeyFile != keyPath {
		t.Fatalf("config path %q", cfg.MasterKeyFile)
	}
	key, err := readMaster(cfg, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if err := app.CheckMaster(context.Background(), cfg, key); err != nil {
		t.Fatal(err)
	}
}

func TestInitPersistsEnvMasterKey(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "keman.yaml")
	dbPath := filepath.Join(dir, "keman.db")
	raw := bytes.Repeat([]byte{7}, 32)
	encoded := base64.StdEncoding.EncodeToString(raw)
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"--config", cfgPath, "init"}, func(k string) string {
		switch k {
		case "KEMAN_DATABASE":
			return dbPath
		case "KEMAN_MASTER_KEY":
			return encoded
		default:
			return ""
		}
	}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code %d\n%s\n%s", code, stdout.String(), stderr.String())
	}
	cfg, err := config.Load(cfgPath, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	got, err := readMaster(cfg, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatal("stored key does not match KEMAN_MASTER_KEY")
	}
}

func TestInitKeepsConfiguredMasterKeyFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "keman.yaml")
	dbPath := filepath.Join(dir, "keman.db")
	keyPath := filepath.Join(dir, "custom.key")
	raw := bytes.Repeat([]byte{3}, 32)
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(raw)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := config.WriteDefault(cfgPath); err != nil {
		t.Fatal(err)
	}
	if err := config.SetMasterKeyFile(cfgPath, keyPath); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"--config", cfgPath, "init"}, func(k string) string {
		if k == "KEMAN_DATABASE" {
			return dbPath
		}
		return ""
	}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code %d\n%s\n%s", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stderr.String(), "master key file:") {
		t.Fatal(stderr.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "master.key")); !os.IsNotExist(err) {
		t.Fatal("created a second master key")
	}
	after, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("rewrote the configured key file")
	}
}

func TestInitRefusesInitializedDatabaseWithoutKey(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "keman.db")
	cfg := config.Defaults()
	cfg.Database = dbPath
	if _, err := app.Init(context.Background(), cfg, bytes.Repeat([]byte{4}, 32)); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"--config", filepath.Join(dir, "keman.yaml"), "init"}, func(k string) string {
		if k == "KEMAN_DATABASE" {
			return dbPath
		}
		return ""
	}, nil, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "already initialized") {
		t.Fatalf("code %d\n%s\n%s", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "master.key")); !os.IsNotExist(err) {
		t.Fatal("created a master key that cannot open the database")
	}
}

func TestInitRecordsKeyForExistingDatabase(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "keman.yaml")
	dbPath := filepath.Join(dir, "keman.db")
	raw := bytes.Repeat([]byte{9}, cryptoenc.KeySize)
	cfg := config.Defaults()
	cfg.Database = dbPath
	if _, err := app.Init(context.Background(), cfg, raw); err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(raw)
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"--config", cfgPath, "init"}, func(k string) string {
		switch k {
		case "KEMAN_DATABASE":
			return dbPath
		case "KEMAN_MASTER_KEY":
			return encoded
		default:
			return ""
		}
	}, nil, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "already initialized") {
		t.Fatalf("code %d\n%s\n%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "master key file:") {
		t.Fatal(stderr.String())
	}
	loaded, err := config.Load(cfgPath, func(k string) string {
		if k == "KEMAN_DATABASE" {
			return dbPath
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := readMaster(loaded, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatal("recorded key does not match")
	}
	if err := app.CheckMaster(context.Background(), loaded, got); err != nil {
		t.Fatal(err)
	}
}
