// Package exposure flags virtual keys that would be easy to abuse if they leaked.
package exposure

import (
	"strconv"
	"time"

	"github.com/kirank55/keman/internal/model"
)

const (
	CodeNetworkOpen  = "network_open"
	CodeNoExpiry     = "no_expiry"
	CodeExpiresSoon  = "expires_soon"
	CodeIdle         = "idle"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	IdleAfter        = 30 * 24 * time.Hour
	ExpiresSoonUnder = 7 * 24 * time.Hour
)

// Finding is one way a leaked copy of the key would be more useful than it needs to be.
type Finding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Fix      string `json:"fix"`
}

// Facts is what Check needs to know about one key.
type Facts struct {
	Ref       string
	Kind      string
	Status    string
	ExpiresAt *time.Time
	CreatedAt time.Time
	LastSeen  time.Time
	CIDRs     []string
	Countries []string
	// Rotated is set on a key that a rotation already replaced. Its expiry
	// is the end of the grace period, not something to fix.
	Rotated bool
}

// Check returns the findings for one key, most severe first. Canary keys,
// and keys that no longer work, have none: they cannot be abused.
func Check(f Facts, now time.Time) []Finding {
	if f.Kind == model.KindCanary || f.Status != model.StatusActive {
		return nil
	}
	if f.ExpiresAt != nil && !now.Before(*f.ExpiresAt) {
		return nil
	}
	var out []Finding
	if len(f.CIDRs) == 0 && len(f.Countries) == 0 {
		out = append(out, Finding{
			Code: CodeNetworkOpen, Severity: SeverityHigh,
			Message: "Works from any address. A leaked copy works for anyone who finds it.",
			Fix:     "keman policy set " + f.Ref + " --cidr <your egress IP>/32",
		})
	}
	last := f.LastSeen
	if last.IsZero() {
		last = f.CreatedAt
	}
	if !last.IsZero() && now.Sub(last) >= IdleAfter {
		msg := "Not used for " + days(now.Sub(last)) + ". An unused key is only useful to someone else."
		if f.LastSeen.IsZero() {
			msg = "Never used, created " + days(now.Sub(f.CreatedAt)) + " ago. An unused key is only useful to someone else."
		}
		out = append(out, Finding{
			Code: CodeIdle, Severity: SeverityMedium, Message: msg,
			Fix: "keman key revoke " + f.Ref,
		})
	}
	switch {
	case f.ExpiresAt == nil:
		out = append(out, Finding{
			Code: CodeNoExpiry, Severity: SeverityMedium,
			Message: "Never expires. A copy leaked years ago still works.",
			Fix:     "keman key expiry " + f.Ref + " 90d",
		})
	case f.ExpiresAt.Sub(now) < ExpiresSoonUnder && !f.Rotated:
		out = append(out, Finding{
			Code: CodeExpiresSoon, Severity: SeverityLow,
			Message: "Expires in " + days(f.ExpiresAt.Sub(now)) + ". Apps using it will start getting 401s.",
			Fix:     "keman key rotate " + f.Ref,
		})
	}
	return out
}

func days(d time.Duration) string {
	n := int(d / (24 * time.Hour))
	switch {
	case n < 1:
		h := int(d / time.Hour)
		if h < 1 {
			return "under an hour"
		}
		if h == 1 {
			return "1 hour"
		}
		return strconv.Itoa(h) + " hours"
	case n == 1:
		return "1 day"
	default:
		return strconv.Itoa(n) + " days"
	}
}
