package detect

import (
	"testing"

	"github.com/kirank55/keman/internal/model"
	"github.com/kirank55/keman/internal/money"
)

func TestScenarios(t *testing.T) {
	checks, err := RunChecks("")
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) != len(CheckNames()) {
		t.Fatalf("len %d", len(checks))
	}
	by := map[string]Check{}
	for _, ch := range checks {
		if ch.Name == "" {
			t.Fatal("blank scenario name")
		}
		if !ch.OK {
			t.Fatalf("%s: %s", ch.Name, ch.Problem)
		}
		by[ch.Name] = ch
	}
	assertHits := func(name string, want ...Hit) {
		t.Helper()
		if !equalHits(by[name].Alerts, want) {
			t.Fatalf("%s alerts %+v", name, by[name].Alerts)
		}
	}
	assertHits("stolen-key", Hit{RuleRate, SevMedium}, Hit{RuleCountry, SevMedium})
	sk := by["stolen-key"]
	if !sk.AutoDisable || !sk.DryRun || !sk.DryChecked || sk.WouldBlock != 1 {
		t.Fatalf("%+v", sk)
	}
	assertHits("spend", Hit{RuleSpend, SevHigh})
	if by["spend"].AutoDisable {
		t.Fatal("spend alone disabled the key")
	}
	assertHits("asn", Hit{RuleASN, SevLow})
	assertHits("allowlist", Hit{RuleAllow, SevMedium})
	assertHits("auth", Hit{RuleAuth, SevMedium})
	if by["auth"].AutoDisable {
		t.Fatal("auth burst disabled the key")
	}
	assertHits("canary", Hit{RuleCanary, SevCritical}, Hit{RuleCanary, SevCritical})
	assertHits("disabled", Hit{RuleDisabled, SevHigh})
	if by["disabled"].AutoDisable {
		t.Fatal("disabled key was auto-disabled")
	}
	if len(by["learning"].Alerts) != 0 || by["learning"].AutoDisable {
		t.Fatalf("%+v", by["learning"])
	}
	assertHits("single-rule", Hit{RuleRate, SevMedium})
	if by["single-rule"].AutoDisable {
		t.Fatal("one rule disabled the key")
	}

	one, err := RunChecks("spend")
	if err != nil || len(one) != 1 || one[0].Name != "spend" {
		t.Fatalf("%v %+v", err, one)
	}
	if _, err := RunChecks("nope"); err == nil {
		t.Fatal("unknown scenario")
	}
	suite := Summarize(checks)
	if !suite.OK || suite.Passed != len(checks) || suite.Failed != 0 {
		t.Fatalf("%+v", suite)
	}
}

func TestReplayLearnedOpensSpend(t *testing.T) {
	cost := int64(5*money.Dollar + 1)
	events := []model.Event{{
		Time: scenarioNow(), KeyID: "k", Kind: model.KindStandard,
		Country: "US", ASN: 64500, Status: 200, CostMicro: &cost,
		Mode: model.ModeAutoDisable,
	}}
	cold := ReplayEvents(events, Options{})
	if got := alertHits(cold); len(got) != 0 {
		t.Fatalf("cold %+v", got)
	}
	warm := ReplayEvents(events, Options{Learned: true})
	if got := alertHits(warm); !equalHits(got, []Hit{{RuleSpend, SevHigh}}) {
		t.Fatalf("warm %+v", got)
	}
	if warm.AutoDisable {
		t.Fatal("one spend detection disabled the key")
	}

	other := events[0]
	other.KeyID = "b"
	both := ReplayEvents([]model.Event{events[0], other}, Options{Learned: true})
	n := 0
	for _, f := range both.Fired {
		if f.Alert && f.Rule == RuleSpend {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("per-key learned baselines fired %d: %+v", n, both.Fired)
	}
}
