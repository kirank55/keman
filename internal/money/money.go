// Package money is integer microdollars. One dollar is 1_000_000.
package money

import (
	"fmt"
	"math/big"
	"strings"
)

const Dollar int64 = 1_000_000

// ParseUSD converts a decimal dollar string to microdollars.
// "1.50" is 1_500_000. More than six fractional digits is an error.
func ParseUSD(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty amount")
	}
	neg := false
	if s[0] == '-' {
		neg = true
		s = s[1:]
	}
	whole, frac, hasFrac := strings.Cut(s, ".")
	if whole == "" {
		whole = "0"
	}
	if !digits(whole) || (hasFrac && !digits(frac)) {
		return 0, fmt.Errorf("invalid amount %q", s)
	}
	if len(frac) > 6 {
		return 0, fmt.Errorf("amount %q has more than 6 decimal places", s)
	}
	for len(frac) < 6 {
		frac += "0"
	}
	w := new(big.Int)
	if _, ok := w.SetString(whole, 10); !ok {
		return 0, fmt.Errorf("invalid amount %q", s)
	}
	w.Mul(w, big.NewInt(Dollar))
	f := new(big.Int)
	if frac != "" {
		if _, ok := f.SetString(frac, 10); !ok {
			return 0, fmt.Errorf("invalid amount %q", s)
		}
	}
	w.Add(w, f)
	if !w.IsInt64() {
		return 0, fmt.Errorf("amount overflows")
	}
	v := w.Int64()
	if neg {
		v = -v
	}
	return v, nil
}

// FormatUSD renders microdollars as a dollar string with up to 6 decimals.
func FormatUSD(micro int64) string {
	neg := micro < 0
	if neg {
		micro = -micro
	}
	whole := micro / Dollar
	frac := micro % Dollar
	s := fmt.Sprintf("%d.%06d", whole, frac)
	s = strings.TrimRight(s, "0")
	s = strings.TrimRight(s, ".")
	if neg {
		s = "-" + s
	}
	return s
}

func digits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// TokenCost is tokens × microdollars-per-million, rounded half up.
func TokenCost(tokens, microPerMillion int64) int64 {
	return tokenCost(tokens, microPerMillion, false)
}

// TokenCostUp rounds up. Reservations use it so a cap is not under-held.
func TokenCostUp(tokens, microPerMillion int64) int64 {
	return tokenCost(tokens, microPerMillion, true)
}

func tokenCost(tokens, microPerMillion int64, up bool) int64 {
	if tokens <= 0 || microPerMillion <= 0 {
		return 0
	}
	n := new(big.Int).Mul(big.NewInt(tokens), big.NewInt(microPerMillion))
	div := big.NewInt(1_000_000)
	if up {
		n.Add(n, big.NewInt(999_999))
	} else {
		n.Add(n, big.NewInt(500_000))
	}
	n.Quo(n, div)
	if !n.IsInt64() {
		return 1<<63 - 1
	}
	return n.Int64()
}
