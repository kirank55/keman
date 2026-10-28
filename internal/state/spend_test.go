package state

import (
	"testing"
	"time"

	"github.com/kirank55/keman/internal/model"
)

func TestSpendSnapshot(t *testing.T) {
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	s := New(nil, 60, time.Second)
	s.LoadSpend([]model.SpendRow{
		{KeyID: "k", Period: DayPeriod(now), Micro: 1_500_000},
		{KeyID: "k", Period: MonthPeriod(now), Micro: 4_000_000},
	})
	if !s.Reserve("k", 100_000, now) {
		t.Fatal("reserve")
	}
	day, month, open := s.Spend("k", now)
	if day != 1_500_000 || month != 4_000_000 || open != 100_000 {
		t.Fatalf("day %d month %d open %d", day, month, open)
	}
}
