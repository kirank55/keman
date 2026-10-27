package alert

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
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
