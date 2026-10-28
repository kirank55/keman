package alert

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/kirank55/keman/internal/model"
)

func TestSignatureVector(t *testing.T) {
	secret := "whsec_test"
	body := []byte(`{"hello":"world"}`)
	const ts = 1700000000
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("1700000000.{\"hello\":\"world\"}"))
	want := hex.EncodeToString(mac.Sum(nil))
	if got := Sign(secret, ts, body); got != want {
		t.Fatalf("got %s want %s", got, want)
	}
	if got := HeaderValue(secret, ts, body); got != "t=1700000000,v1="+want {
		t.Fatalf("header %s", got)
	}
}

func TestSlackTextLeadsWithWhoAndWhere(t *testing.T) {
	a := model.Alert{
		Rule: "new_country", Severity: "medium", KeyID: "abc12345", KeyName: "laptop",
		Observed: map[string]any{"ip": "203.0.113.9", "country": "DE", "asn": 64500, "operation": "POST /v1/chat/completions"},
		Actions: []model.AlertAction{
			{When: "Not you: issue a replacement and revoke the leaked key now", Command: "keman key rotate abc12345 --grace 0"},
		},
	}
	got := slackText(a)
	for _, want := range []string{
		"[medium] new_country on virtual key laptop (abc12345) from 203.0.113.9 (DE, AS64500) calling POST /v1/chat/completions",
		"what to do:",
		"    keman key rotate abc12345 --grace 0",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in:\n%s", want, got)
		}
	}
}
