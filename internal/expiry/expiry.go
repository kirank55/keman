// Package expiry reads the expiry and duration forms the CLI and UI accept.
package expiry

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Span reads a duration. On top of Go durations it accepts whole days
// and weeks, such as 30d and 2w.
func Span(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "0" {
		return 0, nil
	}
	for suffix, unit := range map[string]time.Duration{"d": 24 * time.Hour, "w": 7 * 24 * time.Hour} {
		if n, ok := strings.CutSuffix(s, suffix); ok {
			v, err := strconv.Atoi(n)
			if err != nil || v < 0 {
				return 0, fmt.Errorf("%q is not a duration such as 30d, 12h or 2w", s)
			}
			return time.Duration(v) * unit, nil
		}
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("%q is not a duration such as 30d, 12h or 2w", s)
	}
	return d, nil
}

// Parse reads "never", a span from now (30d), a date (00:00 UTC that
// day), or an RFC3339 time. nil means never.
func Parse(s string, now time.Time) (*time.Time, error) {
	s = strings.TrimSpace(s)
	if strings.EqualFold(s, "never") {
		return nil, nil
	}
	var at time.Time
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		at = t
	} else if t, err := time.Parse("2006-01-02", s); err == nil {
		at = t
	} else if d, err := Span(s); err == nil && d > 0 {
		at = now.Add(d)
	} else {
		return nil, fmt.Errorf("%q is not 30d, 2026-12-31, an RFC3339 time, or never", s)
	}
	at = at.UTC().Truncate(time.Second)
	if !at.After(now) {
		return nil, fmt.Errorf("%s is in the past", at.Format(time.RFC3339))
	}
	return &at, nil
}
