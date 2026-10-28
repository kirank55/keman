package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestExampleFileKeepsDurationStrings(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	path := filepath.Join(filepath.Dir(file), "..", "..", "examples", "keman.yaml")
	cfg, err := Load(path, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SpendFlushInterval != 5*time.Second {
		t.Fatalf("flush %s", cfg.SpendFlushInterval)
	}
	if cfg.EventRetention != 14*24*time.Hour {
		t.Fatalf("events %s", cfg.EventRetention)
	}
	if cfg.SpendFailClosedAfter != time.Minute {
		t.Fatalf("fail closed %s", cfg.SpendFailClosedAfter)
	}
	if cfg.ProxyListen != "0.0.0.0:8080" || cfg.InvalidKeyRPM != 60 {
		t.Fatalf("%+v", cfg)
	}
}

func TestWriteIfAbsentRecordsEffectiveSettings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keman.yaml")
	cfg := Defaults()
	cfg.Database = filepath.Join(dir, "custom.db")
	cfg.MasterKeyFile = filepath.Join(dir, "master.key")
	if err := WriteIfAbsent(path, cfg); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "custom.db") || !strings.Contains(string(raw), "master.key") {
		t.Fatalf("%s", raw)
	}
	if !strings.Contains(string(raw), "event_retention: 336h") {
		t.Fatalf("duration %s", raw)
	}
	loaded, err := Load(path, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Database != cfg.Database || loaded.MasterKeyFile != cfg.MasterKeyFile {
		t.Fatalf("%+v", loaded)
	}
}

func TestAdminURL(t *testing.T) {
	if got := AdminURL(Config{AdminListen: "0.0.0.0:9090"}); got != "http://127.0.0.1:9090" {
		t.Fatal(got)
	}
	if got := AdminURL(Config{AdminListen: "unix:///tmp/k.sock"}); got != "unix:///tmp/k.sock" {
		t.Fatal(got)
	}
	if !AdminIsLocal(Config{AdminListen: "127.0.0.1:8081"}) || AdminIsLocal(Config{AdminListen: "0.0.0.0:8081"}) {
		t.Fatal("local")
	}
}
