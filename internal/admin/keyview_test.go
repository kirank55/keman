package admin

import (
	"context"
	"testing"
	"time"

	"github.com/kirank55/keman/internal/clock"
	"github.com/kirank55/keman/internal/model"
	"github.com/kirank55/keman/internal/state"
)

func TestKeyViewIncludesSpend(t *testing.T) {
	now := time.Date(2026, 10, 27, 15, 0, 0, 0, time.UTC)
	clk := clock.NewFake(now)
	st := state.New(clk, 60, time.Second)
	st.PutKey(model.VirtualKey{
		ID: "k", CredentialID: "c", Name: "laptop",
		Kind: model.KindStandard, Status: model.StatusActive,
	})
	daily := int64(2_000_000)
	st.PutPolicy(state.Policy{Policy: model.Policy{
		KeyID: "k", Mode: model.ModeAlertOnly, DailyCapMicro: &daily,
	}})
	st.LoadSpend([]model.SpendRow{
		{KeyID: "k", Period: state.DayPeriod(now), Micro: 420_000},
		{KeyID: "k", Period: state.MonthPeriod(now), Micro: 4_200_000},
	})
	if !st.Reserve("k", 100_000, now) {
		t.Fatal("reserve")
	}
	h := &Handler{Service: &Service{State: st, Clock: clk}}
	views := h.keyViews(context.Background())
	if len(views) != 1 {
		t.Fatal(len(views))
	}
	if views[0]["spend_today_microusd"].(int64) != 420_000 {
		t.Fatal(views[0]["spend_today_microusd"])
	}
	if views[0]["spend_month_microusd"].(int64) != 4_200_000 {
		t.Fatal(views[0]["spend_month_microusd"])
	}
	if views[0]["spend_open_microusd"].(int64) != 100_000 {
		t.Fatal(views[0]["spend_open_microusd"])
	}
}

func TestKeyViewsSortByName(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 27, 15, 0, 0, 0, time.UTC))
	st := state.New(clk, 60, time.Second)
	for id, name := range map[string]string{"a1": "prod-api", "b2": "ci", "c3": "laptop (rotated)", "d4": "laptop", "e5": "ci"} {
		st.PutKey(model.VirtualKey{ID: id, CredentialID: "c", Name: name, Kind: model.KindStandard, Status: model.StatusActive})
	}
	h := &Handler{Service: &Service{State: st, Clock: clk}}
	var got []string
	for _, v := range h.keyViews(context.Background()) {
		got = append(got, v["id"].(string))
	}
	want := []string{"b2", "e5", "d4", "c3", "a1"}
	for i := range want {
		if i >= len(got) || got[i] != want[i] {
			t.Fatalf("order %v, want %v", got, want)
		}
	}
}
