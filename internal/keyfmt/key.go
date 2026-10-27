// Package keyfmt parses and generates virtual keys.
// A virtual key is kmn_<id>_<secret>. The id is 8 base62 characters.
// The secret is 32 random bytes, base62, shown once. Only the hash is stored.
package keyfmt

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

const (
	Prefix      = "kmn_"
	AdminPrefix = "kma_"
	idLen       = 8
	secretBytes = 32
	// 62^43 is the smallest power that covers 256 bits.
	secretLen = 43
	alphabet  = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

var ErrInvalid = errors.New("invalid virtual key")

// Parse splits a virtual key. The secret must be base62 and at least 16
// characters so a truncated copy is not treated as a key.
func Parse(token string) (id, secret string, err error) {
	if !strings.HasPrefix(token, Prefix) {
		return "", "", ErrInvalid
	}
	rest := token[len(Prefix):]
	i := strings.IndexByte(rest, '_')
	if i < 0 {
		return "", "", ErrInvalid
	}
	id, secret = rest[:i], rest[i+1:]
	if len(id) != idLen || !isBase62(id) || len(secret) < 16 || !isBase62(secret) {
		return "", "", ErrInvalid
	}
	return id, secret, nil
}

// Hash is SHA-256 of the secret portion only.
func Hash(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

// MatchHash compares a secret to a stored hash in constant time.
// A secret that does not parse still takes a comparison against dummy.
func MatchHash(secret string, want []byte, dummy []byte) bool {
	got := Hash(secret)
	if len(want) != len(got) {
		subtle.ConstantTimeCompare(got, dummy)
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

// Generate returns id, secret, and the full virtual key.
func Generate() (id, secret, token string, err error) {
	id, err = randBase62(idLen)
	if err != nil {
		return "", "", "", err
	}
	raw := make([]byte, secretBytes)
	if _, err = rand.Read(raw); err != nil {
		return "", "", "", err
	}
	secret = encodeFixed(raw, secretLen)
	token = Prefix + id + "_" + secret
	return id, secret, token, nil
}

// GenerateAdminToken returns a token that is not a virtual key.
func GenerateAdminToken() (string, error) {
	raw := make([]byte, secretBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return AdminPrefix + encodeFixed(raw, secretLen), nil
}

// HashToken hashes an admin token or any other high-entropy string.
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

func isBase62(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune(alphabet, c) {
			return false
		}
	}
	return true
}

func randBase62(n int) (string, error) {
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		for {
			var b [1]byte
			if _, err := rand.Read(b[:]); err != nil {
				return "", err
			}
			// 248 = 4*62, so the modulo is unbiased below this cutoff.
			if b[0] < 248 {
				out[i] = alphabet[int(b[0])%62]
				break
			}
		}
	}
	return string(out), nil
}

func encodeFixed(b []byte, width int) string {
	n := new(big.Int).SetBytes(b)
	var digits []byte
	base := big.NewInt(62)
	zero := big.NewInt(0)
	mod := new(big.Int)
	for n.Cmp(zero) > 0 {
		n.DivMod(n, base, mod)
		digits = append(digits, alphabet[mod.Int64()])
	}
	for i, j := 0, len(digits)-1; i < j; i, j = i+1, j-1 {
		digits[i], digits[j] = digits[j], digits[i]
	}
	s := string(digits)
	if len(s) > width {
		return s
	}
	return strings.Repeat("0", width-len(s)) + s
}

// NewID returns prefix + "_" + n base62 characters.
func NewID(prefix string, n int) (string, error) {
	s, err := randBase62(n)
	if err != nil {
		return "", err
	}
	if prefix == "" {
		return s, nil
	}
	return fmt.Sprintf("%s_%s", prefix, s), nil
}
