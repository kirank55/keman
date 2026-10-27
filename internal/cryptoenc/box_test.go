package cryptoenc

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestRoundTripAndRekey(t *testing.T) {
	master := bytes.Repeat([]byte{1}, 32)
	dek, err := GenerateDEK()
	if err != nil {
		t.Fatal(err)
	}
	nonce, wrapped, err := WrapDEK(master, dek)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnwrapDEK(master, nonce, wrapped)
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatal(err)
	}
	box, err := NewBox(dek)
	if err != nil {
		t.Fatal(err)
	}
	n, ct, err := box.Encrypt([]byte("cred_1"), []byte("sk-live"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := box.Decrypt([]byte("cred_1"), n, ct)
	if err != nil || string(plain) != "sk-live" {
		t.Fatal(err)
	}
	if _, err := box.Decrypt([]byte("cred_2"), n, ct); err == nil {
		t.Fatal("swapped credential id was accepted")
	}
	other := bytes.Repeat([]byte{2}, 32)
	n2, w2, err := WrapDEK(other, dek)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnwrapDEK(master, n2, w2); err == nil {
		t.Fatal("old master unwrapped the new wrap")
	}
	b64 := base64.StdEncoding.EncodeToString(master)
	parsed, err := ParseMasterKey([]byte(b64))
	if err != nil || !bytes.Equal(parsed, master) {
		t.Fatal(err)
	}
}
