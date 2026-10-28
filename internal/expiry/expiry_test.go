package expiry

import (
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	for in, want := range map[string]string{
		"30d":                  "2026-11-27T12:00:00Z",
		"2w":                   "2026-11-11T12:00:00Z",
		"36h":                  "2026-10-30T00:00:00Z",
		"2026-12-31":           "2026-12-31T00:00:00Z",
		"2027-01-02T03:04:05Z": "2027-01-02T03:04:05Z",
	} {
		got, err := Parse(in, now)
		if err != nil || got == nil || got.Format(time.RFC3339) != want {
			t.Errorf("%s: %v %v", in, got, err)
		}
	}
	if got, err := Parse("never", now); got != nil || err != nil {
		t.Errorf("never: %v %v", got, err)
	}
	for _, bad := range []string{"", "soon", "-3d", "2020-01-01", "0"} {
		if _, err := Parse(bad, now); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if d, err := Span("0"); err != nil || d != 0 {
		t.Errorf("span 0: %v %v", d, err)
	}
}
