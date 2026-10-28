package state

import (
	"math"
	"testing"
	"time"

	"github.com/kirank55/keman/internal/clock"
	"github.com/kirank55/keman/internal/model"
)

func TestReserveDoesNotWrapPastCap(t *testing.T) {
	st := New(clock.System{}, 60, time.Minute)
	cap := int64(1_000_000)
	st.PutPolicy(Policy{Policy: model.Policy{KeyID: "k", DailyCapMicro: &cap}})
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	if !st.Reserve("k", 10, now) {
		t.Fatal("small hold")
	}
	if st.Reserve("k", math.MaxInt64, now) {
		t.Fatal("overflow hold was accepted")
	}
	if st.open["k"] != 10 {
		t.Fatalf("open %d", st.open["k"])
	}
}

func TestReconcileUsesCallerPeriod(t *testing.T) {
	st := New(clock.System{}, 60, time.Minute)
	cap := int64(2_000_000)
	st.PutPolicy(Policy{Policy: model.Policy{KeyID: "k", DailyCapMicro: &cap}})
	day1 := time.Date(2026, 10, 27, 23, 59, 0, 0, time.UTC)
	day2 := time.Date(2026, 10, 28, 0, 1, 0, 0, time.UTC)
	if !st.Reserve("k", 500_000, day1) {
		t.Fatal("reserve")
	}
	st.Reconcile("k", 500_000, 500_000, day1)
	if st.committed("k", DayPeriod(day1)) != 500_000 {
		t.Fatalf("day1 %d", st.committed("k", DayPeriod(day1)))
	}
	if st.committed("k", DayPeriod(day2)) != 0 {
		t.Fatalf("day2 %d", st.committed("k", DayPeriod(day2)))
	}
}
