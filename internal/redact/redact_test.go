package redact

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestScrubsVirtualKeysAndAddedSecrets(t *testing.T) {
	var buf bytes.Buffer
	secrets := &Secrets{}
	secrets.Add("sk-test-REALKEY-xyz")
	h := New(slog.NewTextHandler(&buf, nil), secrets)
	log := slog.New(h)
	log.Info("request", "msg", "saw kmn_abcd1234_abcdefghijklmnopqrstuvwxyz012345 and sk-test-REALKEY-xyz")
	out := buf.String()
	if strings.Contains(out, "kmn_abcd1234_") || strings.Contains(out, "sk-test-REALKEY-xyz") {
		t.Fatal(out)
	}
}

func TestAddIsIdempotentAndScrubsAny(t *testing.T) {
	secrets := &Secrets{}
	secrets.Add("sk-test-REALKEY-xyz")
	secrets.Add("sk-test-REALKEY-xyz")
	if secrets.Len() != 1 {
		t.Fatalf("len %d", secrets.Len())
	}
	var buf bytes.Buffer
	log := slog.New(New(slog.NewTextHandler(&buf, nil), secrets))
	type wrap struct{ S string }
	log.Info("x", slog.Any("w", wrap{S: "sk-test-REALKEY-xyz"}))
	log.Info("admin", "token", "kma_abcdefghijklmnopqrstuvwxyz0123456789abc")
	out := buf.String()
	if strings.Contains(out, "sk-test-REALKEY-xyz") {
		t.Fatal(out)
	}
	if strings.Contains(out, "kma_abcdefghijklmnopqrstuvwxyz0123456789abc") {
		t.Fatal(out)
	}
}
