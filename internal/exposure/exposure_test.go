package exposure

import (
	"testing"
	"time"

	"github.com/kirank55/keman/internal/model"
)

func codes(fs []Finding) map[string]bool {
	out := map[string]bool{}
	for _, f := range fs {
		out[f.Code] = true
	}
	return out
}

func TestCheck(t *testing.T) {
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	soon := now.Add(48 * time.Hour)
	later := now.Add(60 * 24 * time.Hour)
	past := now.Add(-time.Hour)
	base := Facts{Ref: "k", Kind: model.KindStandard, Status: model.StatusActive, CreatedAt: now.Add(-time.Hour), LastSeen: now}

	open := Check(base, now)
	if c := codes(open); !c[CodeNetworkOpen] || !c[CodeNoExpiry] || c[CodeIdle] || open[0].Code != CodeNetworkOpen {
		t.Fatalf("open key %+v", open)
	}

	locked := base
	locked.CIDRs = []string{"10.0.0.0/8"}
	locked.ExpiresAt = &later
	if got := Check(locked, now); len(got) != 0 {
		t.Fatalf("locked key %+v", got)
	}

	locked.ExpiresAt = &soon
	if c := codes(Check(locked, now)); !c[CodeExpiresSoon] {
		t.Fatal("expiry soon not flagged")
	}

	locked.Rotated = true
	if c := codes(Check(locked, now)); c[CodeExpiresSoon] {
		t.Fatal("a rotated key was told to rotate")
	}
	locked.Rotated = false

	idle := locked
	idle.ExpiresAt = &later
	idle.LastSeen = time.Time{}
	idle.CreatedAt = now.Add(-40 * 24 * time.Hour)
	if c := codes(Check(idle, now)); !c[CodeIdle] {
		t.Fatal("never-used key not flagged")
	}

	for name, f := range map[string]Facts{
		"canary":   {Kind: model.KindCanary, Status: model.StatusActive},
		"disabled": {Kind: model.KindStandard, Status: model.StatusDisabled},
		"expired":  {Kind: model.KindStandard, Status: model.StatusActive, ExpiresAt: &past},
	} {
		if got := Check(f, now); len(got) != 0 {
			t.Fatalf("%s: %+v", name, got)
		}
	}
}
