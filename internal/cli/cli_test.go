package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHelpAndUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"help"}, nil, nil, &stdout, &stderr); code != 0 {
		t.Fatalf("help %d", code)
	}
	if !strings.Contains(stdout.String(), "keman "+Version) {
		t.Fatalf("help %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "base_url") {
		t.Fatal("help should mention SDK base_url")
	}
	stdout.Reset()
	stderr.Reset()
	if code := Run(context.Background(), nil, nil, nil, &stdout, &stderr); code != 2 {
		t.Fatalf("no args %d", code)
	}
	stderr.Reset()
	if code := Run(context.Background(), []string{"nope"}, nil, nil, &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "unknown command") {
		t.Fatalf("unknown %d %s", code, stderr.String())
	}
}

func TestConfigFlagAfterCommand(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "keman.yaml")
	var stderr bytes.Buffer
	code := Run(context.Background(), []string{"init", "--config", cfg}, func(string) string { return "" }, nil, &bytes.Buffer{}, &stderr)
	if strings.Contains(stderr.String(), "init takes no arguments") {
		t.Fatalf("global flag after command was rejected: %s", stderr.String())
	}
	if code != 1 || !strings.Contains(stderr.String(), "KEMAN_MASTER_KEY") {
		t.Fatalf("code %d %s", code, stderr.String())
	}
}

func TestInitWritesEffectiveDatabase(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "keman.yaml")
	dbPath := filepath.Join(dir, "data", "keman.db")
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"--config", cfgPath, "init"}, func(k string) string {
		if k == "KEMAN_MASTER_KEY" {
			return "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
		}
		if k == "KEMAN_DATABASE" {
			return dbPath
		}
		return ""
	}, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code %d\n%s\n%s", code, stdout.String(), stderr.String())
	}
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), dbPath) {
		t.Fatalf("yaml did not record the database path:\n%s", raw)
	}
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "KEMAN_ADMIN_TOKEN") {
		t.Fatalf("missing next steps: %s", stdout.String())
	}
}

func TestUnixPathParse(t *testing.T) {
	p, ok := unixPath("unix:///tmp/keman.sock")
	if !ok || p != "/tmp/keman.sock" {
		t.Fatalf("%q %v", p, ok)
	}
	if _, ok := unixPath("http://127.0.0.1:8081"); ok {
		t.Fatal("http url")
	}
}
