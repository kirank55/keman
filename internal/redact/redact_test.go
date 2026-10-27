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
