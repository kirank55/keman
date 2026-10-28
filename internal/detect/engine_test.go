package detect

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/kirank55/keman/internal/clock"
	"github.com/kirank55/keman/internal/model"
)

func TestReplayAttackAutoDisablesAndDryRunMatches(t *testing.T) {
	start := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	clk := clock.NewFake(start)
	events := attackEvents(t, clk)
	raw, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadFixture(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != len(events) {
		t.Fatalf("loaded %d", len(loaded))
	}

	auto := play(clk, loaded, model.ModeAutoDisable)
	var disabledAt time.Time
	var alerts []string
	for i, out := range auto {
		for _, a := range out.Alerts {
			alerts = append(alerts, a.Rule+":"+a.Severity)
		}
		if out.DisableKey {
			disabledAt = loaded[i].Time
		}
	}
	if disabledAt.IsZero() {
		t.Fatal("auto-disable did not trip")
	}
	joined := stringsJoin(alerts)
	for _, want := range []string{"rate_spike:medium", "new_country:medium"} {
		if !stringsContains(joined, want) {
			t.Fatalf("alerts %v", alerts)
		}
	}

	dry := play(clk, loaded, model.ModeDryRun)
	tripped := false
	blocked := 0
	for _, out := range dry {
		if out.DryRunTrip {
			tripped = true
		}
		if out.WouldBlock {
			blocked++
		}
		if out.DisableKey {
			t.Fatal("dry-run disabled the key")
		}
	}
	if !tripped || blocked == 0 {
		t.Fatalf("tripped %v blocked %d", tripped, blocked)
	}
}

func play(clk *clock.Fake, rows []model.Event, mode string) []Outcome {
	eng := New(clk, DefaultConfig())
	eng.LoadBaseline(model.Baseline{
		KeyID:        "key_attack",
		FirstSeen:    clk.Now().Add(-8 * 24 * time.Hour),
		RequestCount: 500,
		Countries:    map[string]time.Time{"US": clk.Now().Add(-8 * 24 * time.Hour)},
		ASNs:         map[int]time.Time{64500: clk.Now().Add(-8 * 24 * time.Hour)},
	})
	var out []Outcome
	for _, ev := range rows {
		ev.Mode = mode
		ev.KeyID = "key_attack"
		out = append(out, eng.Observe(ev))
	}
	return out
}

type fixRow struct {
	Time        time.Time `json:"time"`
	KeyID       string    `json:"key_id"`
	IP          string    `json:"ip"`
	Country     string    `json:"country"`
	ASN         int       `json:"asn"`
	Status      int       `json:"status"`
	BlockedCode string    `json:"blocked_code"`
	Mode        string    `json:"mode"`
	CostMicro   *int64    `json:"cost_micro"`
}

func attackEvents(t *testing.T, clk *clock.Fake) []fixRow {
	t.Helper()
	var rows []fixRow
	cost := int64(1)
	for i := 0; i < 102; i++ {
		rows = append(rows, fixRow{
			Time: clk.Now(), KeyID: "key_attack", IP: "203.0.113.8", Country: "US", ASN: 64500,
			Status: 200, CostMicro: &cost, Mode: model.ModeAutoDisable,
		})
	}
	clk.Advance(time.Minute)
	rows = append(rows, fixRow{
		Time: clk.Now(), KeyID: "key_attack", IP: "198.51.100.9", Country: "DE", ASN: 64500,
		Status: 200, CostMicro: &cost, Mode: model.ModeAutoDisable,
	})
	clk.Advance(time.Minute)
	rows = append(rows, fixRow{
		Time: clk.Now(), KeyID: "key_attack", IP: "198.51.100.9", Country: "DE", ASN: 64500,
		Status: 200, Mode: model.ModeAutoDisable,
	})
	return rows
}

func TestExpiredKeyDoesNotFeedBehaviorRules(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	eng := New(clk, DefaultConfig())
	eng.LoadBaseline(model.Baseline{
		KeyID: "k", FirstSeen: clk.Now().Add(-8 * 24 * time.Hour), RequestCount: 500,
		Countries: map[string]time.Time{"US": clk.Now().Add(-8 * 24 * time.Hour)},
	})
	for i := 0; i < 102; i++ {
		out := eng.Observe(model.Event{
			Time: clk.Now(), KeyID: "k", Kind: model.KindStandard, IP: "203.0.113.8",
			Country: "DE", Status: 401, BlockedCode: "key_expired", Mode: model.ModeAutoDisable,
		})
		for _, a := range out.Alerts {
			if a.Rule == RuleRate || a.Rule == RuleCountry {
				t.Fatalf("expired key fired %s", a.Rule)
			}
		}
		if out.DisableKey {
			t.Fatal("expired key auto-disabled")
		}
	}
}

func TestCommandsUsesIPv6HostPrefix(t *testing.T) {
	cmds := Commands("abc12345", "2001:db8::1", "US")
	joined := stringsJoin(cmds)
	if !stringsContains(joined, "2001:db8::1/128") {
		t.Fatalf("%v", cmds)
	}
	if stringsContains(joined, "2001:db8::1/32") {
		t.Fatalf("IPv6 /32: %v", cmds)
	}
}

func TestCanaryFiresDuringLearning(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	eng := New(clk, DefaultConfig())
	out := eng.Observe(model.Event{
		Time: clk.Now(), KeyID: "k", Kind: model.KindCanary, IP: "203.0.113.1", Status: 401, BlockedCode: "canary_used",
	})
	if len(out.Alerts) != 1 || out.Alerts[0].Severity != SevCritical || out.Alerts[0].Rule != RuleCanary {
		t.Fatalf("%+v", out.Alerts)
	}
	clk.Advance(time.Hour)
	again := eng.Observe(model.Event{
		Time: clk.Now(), KeyID: "k", Kind: model.KindCanary, Status: 401, BlockedCode: "canary_used",
	})
	if len(again.Alerts) != 1 {
		t.Fatal("quiet hour should open a new alert")
	}
}

func stringsJoin(in []string) string {
	out := ""
	for _, s := range in {
		out += s + ","
	}
	return out
}

func stringsContains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
