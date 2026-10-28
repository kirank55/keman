// Package cryptoenc is envelope encryption for credentials.
// The master key wraps one data key. The data key encrypts each credential
// with AES-256-GCM. The credential id is the associated data.
package cryptoenc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

const KeySize = 32

var (
	ErrKeySize = errors.New("master key must be 32 bytes")
	dekAAD     = []byte("keman-dek-v1")
)

// Box encrypts with a data key that is already unwrapped.
type Box struct {
	aead cipher.AEAD
}

func NewBox(dek []byte) (*Box, error) {
	return newBox(dek)
}

func newBox(key []byte) (*Box, error) {
	if len(key) != KeySize {
		return nil, ErrKeySize
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

func (b *Box) Encrypt(aad, plaintext []byte) (nonce, ciphertext []byte, err error) {
	nonce = make([]byte, b.aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	ciphertext = b.aead.Seal(nil, nonce, plaintext, aad)
	return nonce, ciphertext, nil
}

func (b *Box) Decrypt(aad, nonce, ciphertext []byte) ([]byte, error) {
	if len(nonce) != b.aead.NonceSize() {
		return nil, errors.New("bad nonce")
	}
	plain, err := b.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, err
	}
	return plain, nil
}

// GenerateDEK returns a fresh data key.
func GenerateDEK() ([]byte, error) {
	b := make([]byte, KeySize)
	_, err := rand.Read(b)
	return b, err
}

// WrapDEK encrypts the data key with the master key.
func WrapDEK(master, dek []byte) (nonce, wrapped []byte, err error) {
	box, err := newBox(master)
	if err != nil {
		return nil, nil, err
	}
	if len(dek) != KeySize {
		return nil, nil, ErrKeySize
	}
	return box.Encrypt(dekAAD, dek)
}

// UnwrapDEK recovers the data key. A wrong master key returns an error.
func UnwrapDEK(master, nonce, wrapped []byte) ([]byte, error) {
	box, err := newBox(master)
	if err != nil {
		return nil, err
	}
	return box.Decrypt(dekAAD, nonce, wrapped)
}

// ParseMasterKey accepts standard base64, raw base64, hex, or 32 raw bytes.
// A buffer that is already 32 bytes is used as-is, including trailing
// spaces that are part of a binary key. A single trailing newline is
// stripped next so `openssl rand 32` files that gained a newline still
// work. Spaces are only trimmed when decoding a text encoding.
func ParseMasterKey(b []byte) ([]byte, error) {
	if len(b) == KeySize {
		out := make([]byte, KeySize)
		copy(out, b)
		return out, nil
	}
	nl := trimCRLF(b)
	if len(nl) == KeySize {
		out := make([]byte, KeySize)
		copy(out, nl)
		return out, nil
	}
	s := trimSpace(b)
	if key, err := decodeBase64(s); err == nil && len(key) == KeySize {
		return key, nil
	}
	if key, err := decodeHex(s); err == nil && len(key) == KeySize {
		return key, nil
	}
	return nil, fmt.Errorf("%w (got %d bytes after decode)", ErrKeySize, len(s))
}

func trimCRLF(b []byte) []byte {
	i := 0
	j := len(b)
	for i < j && (b[i] == '\n' || b[i] == '\r') {
		i++
	}
	for j > i && (b[j-1] == '\n' || b[j-1] == '\r') {
		j--
	}
	return b[i:j]
}

func trimSpace(b []byte) []byte {
	i := 0
	j := len(b)
	for i < j && (b[i] == ' ' || b[i] == '\n' || b[i] == '\r' || b[i] == '\t') {
		i++
	}
	for j > i && (b[j-1] == ' ' || b[j-1] == '\n' || b[j-1] == '\r' || b[j-1] == '\t') {
		j--
	}
	return b[i:j]
}

func decodeBase64(s []byte) ([]byte, error) {
	encodings := []func(string) ([]byte, error){
		decodeStd,
		decodeRawStd,
		decodeURL,
		decodeRawURL,
	}
	var last error
	for _, fn := range encodings {
		out, err := fn(string(s))
		if err == nil {
			return out, nil
		}
		last = err
	}
	return nil, last
}

func decodeHex(s []byte) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, errors.New("odd hex")
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		hi, ok := fromHex(s[i*2])
		lo, ok2 := fromHex(s[i*2+1])
		if !ok || !ok2 {
			return nil, errors.New("bad hex")
		}
		out[i] = hi<<4 | lo
	}
	return out, nil
}

func fromHex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}
