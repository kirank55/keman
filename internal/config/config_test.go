package config

import (
	"path/filepath"
	"runtime"
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
