package detect

import (
	"fmt"
	"strings"
	"time"

	"github.com/kirank55/keman/internal/model"
	"github.com/kirank55/keman/internal/money"
)

// Hit is one alert a scenario opened. Repeats inside the quiet hour are
// detections, not extra hits.
type Hit struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
}

// Fired is one detection from a replay. Alert is false when the rule
// already had an open incident.
type Fired struct {
	Time     time.Time      `json:"time"`
	KeyID    string         `json:"virtual_key_id,omitempty"`
	Rule     string         `json:"rule"`
	Severity string         `json:"severity"`
	Alert    bool           `json:"alert"`
	Evidence map[string]any `json:"evidence,omitempty"`
	Commands []string       `json:"commands,omitempty"`
}

// Result is a replay of events through a fresh engine.
type Result struct {
	Events        int        `json:"events"`
	Fired         []Fired    `json:"fired"`
	AutoDisable   bool       `json:"auto_disable"`
	AutoDisableAt *time.Time `json:"auto_disable_at,omitempty"`
	DryRun        bool       `json:"dry_run"`
	DryRunAt      *time.Time `json:"dry_run_at,omitempty"`
	WouldBlock    int        `json:"would_block"`
}

// Options controls ReplayEvents.
type Options struct {
	// Learned seeds each key with a baseline past the learning period:
	// 500 requests, first seen eight days before that key's first event,
	// country US, ASN 64500.
	Learned bool
}

// Check is one built-in scenario compared with what the engine did.
type Check struct {
	Name        string `json:"name"`
	OK          bool   `json:"ok"`
	Alerts      []Hit  `json:"alerts,omitempty"`
	AutoDisable bool   `json:"auto_disable"`
	DryChecked  bool   `json:"-"`
	DryRun      bool   `json:"dry_run,omitempty"`
	WouldBlock  int    `json:"would_block,omitempty"`
	Problem     string `json:"problem,omitempty"`
}

// Suite is the summary of a scenario run.
type Suite struct {
	OK     bool    `json:"ok"`
	Passed int     `json:"passed"`
	Failed int     `json:"failed"`
	Checks []Check `json:"checks"`
}

type scenario struct {
	name string
	run  func() Check
}

func scenarios() []scenario {
	return []scenario{
		{"stolen-key", checkStolenKey},
		{"spend", checkSpend},
		{"asn", checkASN},
		{"allowlist", checkAllowlist},
		{"auth", checkAuth},
		{"canary", checkCanary},
		{"disabled", checkDisabled},
		{"learning", checkLearning},
		{"single-rule", checkSingleRule},
	}
}

// CheckNames are the built-in scenarios, in run order.
func CheckNames() []string {
	out := make([]string, 0, len(scenarios()))
	for _, s := range scenarios() {
		out = append(out, s.name)
	}
	return out
}

// RunChecks replays built-in scenarios on a fresh engine.
// An empty name runs every scenario. Nothing is stored or delivered.
func RunChecks(only string) ([]Check, error) {
	all := scenarios()
	if only != "" {
		found := false
		for _, s := range all {
			if s.name == only {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("unknown scenario %q (%s)", only, strings.Join(CheckNames(), ", "))
		}
	}
	var out []Check
	for _, s := range all {
		if only != "" && s.name != only {
			continue
		}
		ch := s.run()
		ch.Name = s.name
		out = append(out, ch)
	}
	return out, nil
}

// Summarize counts passing scenarios.
func Summarize(checks []Check) Suite {
	s := Suite{OK: true, Checks: checks}
	if s.Checks == nil {
		s.Checks = []Check{}
	}
	for _, ch := range checks {
		if ch.OK {
			s.Passed++
			continue
		}
		s.Failed++
		s.OK = false
	}
	return s
}

// ReplayEvents runs events in file order on a fresh engine.
func ReplayEvents(events []model.Event, opt Options) Result {
	var bases []model.Baseline
	if opt.Learned {
		first := map[string]time.Time{}
		var order []string
		for _, ev := range events {
			if _, ok := first[ev.KeyID]; ok {
				continue
			}
			first[ev.KeyID] = ev.Time
			order = append(order, ev.KeyID)
		}
		for _, id := range order {
			bases = append(bases, learnedBaseline(id, first[id]))
		}
	}
	return run(bases, events)
}

func learnedBaseline(id string, now time.Time) model.Baseline {
	seen := now.Add(-8 * 24 * time.Hour)
	return model.Baseline{
		KeyID:        id,
		FirstSeen:    seen,
		RequestCount: 500,
		Countries:    map[string]time.Time{"US": seen},
		ASNs:         map[int]time.Time{64500: seen},
	}
}

func run(bases []model.Baseline, events []model.Event) Result {
	eng := New(nil, DefaultConfig())
	for _, b := range bases {
		eng.LoadBaseline(b)
	}
	out := Result{Events: len(events), Fired: []Fired{}}
	for _, ev := range events {
		o := eng.Observe(ev)
		if o.DisableKey && !out.AutoDisable {
			t := ev.Time
			out.AutoDisable = true
			out.AutoDisableAt = &t
		}
		if o.DryRunTrip && !out.DryRun {
			t := ev.Time
			out.DryRun = true
			out.DryRunAt = &t
		}
		if o.WouldBlock {
			out.WouldBlock++
		}
		alerts := map[string]model.Alert{}
		for _, a := range o.Alerts {
			alerts[a.Rule] = a
		}
		for _, d := range o.Detections {
			f := Fired{
				Time: d.Time, KeyID: d.KeyID, Rule: d.Rule, Severity: d.Severity, Evidence: d.Evidence,
			}
			if a, ok := alerts[d.Rule]; ok {
				f.Alert = true
				f.Commands = a.Commands
			}
			out.Fired = append(out.Fired, f)
		}
	}
	return out
}

func scenarioNow() time.Time {
	return time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
}

func baseEvent(t time.Time) model.Event {
	return model.Event{
		Time: t, KeyID: "key_test", Kind: model.KindStandard,
		IP: "203.0.113.8", Country: "US", ASN: 64500, Status: 200,
		Mode: model.ModeAutoDisable,
	}
}

func nEvents(n int, mutate func(*model.Event)) []model.Event {
	out := make([]model.Event, n)
	for i := 0; i < n; i++ {
		ev := baseEvent(scenarioNow())
		if mutate != nil {
			mutate(&ev)
		}
		out[i] = ev
	}
	return out
}

func setMode(in []model.Event, mode string) []model.Event {
	out := make([]model.Event, len(in))
	copy(out, in)
	for i := range out {
		out[i].Mode = mode
	}
	return out
}

func runFresh(events []model.Event) Result {
	return run(nil, events)
}

func runLearned(events []model.Event) Result {
	if len(events) == 0 {
		return run(nil, events)
	}
	return run([]model.Baseline{learnedBaseline(events[0].KeyID, events[0].Time)}, events)
}

func alertHits(res Result) []Hit {
	var hits []Hit
	for _, f := range res.Fired {
		if f.Alert {
			hits = append(hits, Hit{Rule: f.Rule, Severity: f.Severity})
		}
	}
	return hits
}

func equalHits(got, want []Hit) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func formatHits(in []Hit) string {
	if len(in) == 0 {
		return "none"
	}
	parts := make([]string, len(in))
	for i, h := range in {
		parts[i] = h.Rule + " " + h.Severity
	}
	return strings.Join(parts, ", ")
}

func expect(res Result, want []Hit, wantAuto bool) Check {
	ch := Check{Alerts: alertHits(res), AutoDisable: res.AutoDisable}
	var probs []string
	if !equalHits(ch.Alerts, want) {
		probs = append(probs, "alerts "+formatHits(ch.Alerts)+"; want "+formatHits(want))
	}
	if ch.AutoDisable != wantAuto {
		if wantAuto {
			probs = append(probs, "auto_disable did not trip")
		} else {
			probs = append(probs, "auto_disable tripped")
		}
	}
	ch.Problem = strings.Join(probs, "; ")
	ch.OK = ch.Problem == ""
	return ch
}

func fail(ch Check, msg string) Check {
	if ch.Problem == "" {
		ch.Problem = msg
	} else {
		ch.Problem += "; " + msg
	}
	ch.OK = false
	return ch
}

func checkStolenKey() Check {
	events := stolenEvents()
	auto := runLearned(events)
	dry := runLearned(setMode(events, model.ModeDryRun))
	ch := expect(auto, []Hit{{Rule: RuleRate, Severity: SevMedium}, {Rule: RuleCountry, Severity: SevMedium}}, true)
	ch.DryChecked = true
	ch.DryRun = dry.DryRun
	ch.WouldBlock = dry.WouldBlock
	if !equalHits(alertHits(dry), alertHits(auto)) {
		ch = fail(ch, "dry_run alerts "+formatHits(alertHits(dry)))
	}
	if auto.DryRun {
		ch = fail(ch, "auto_disable reported a dry run")
	}
	if !dry.DryRun {
		ch = fail(ch, "dry_run did not trip")
	}
	if dry.AutoDisable {
		ch = fail(ch, "dry_run turned the key off")
	}
	if dry.WouldBlock != 1 {
		ch = fail(ch, fmt.Sprintf("dry_run would block %d", dry.WouldBlock))
	}
	return ch
}

func stolenEvents() []model.Event {
	events := nEvents(101, nil)
	de := baseEvent(scenarioNow().Add(time.Minute))
	de.IP = "198.51.100.9"
	de.Country = "DE"
	return append(events, de, baseEvent(scenarioNow().Add(2*time.Minute)))
}

func checkSpend() Check {
	exact := int64(5 * money.Dollar)
	over := exact + 1
	floor := runLearned([]model.Event{withCost(exact)})
	ch := expect(runLearned([]model.Event{withCost(over)}), []Hit{{Rule: RuleSpend, Severity: SevHigh}}, false)
	if len(alertHits(floor)) != 0 {
		ch = fail(ch, "spend at the $5 floor alerted")
	}
	return ch
}

func withCost(v int64) model.Event {
	ev := baseEvent(scenarioNow())
	ev.CostMicro = &v
	return ev
}

func checkASN() Check {
	same := runLearned([]model.Event{withASN(64500)})
	ch := expect(runLearned([]model.Event{withASN(64501)}), []Hit{{Rule: RuleASN, Severity: SevLow}}, false)
	if len(alertHits(same)) != 0 {
		ch = fail(ch, "known ASN alerted")
	}
	return ch
}

func withASN(asn int) model.Event {
	ev := baseEvent(scenarioNow())
	ev.ASN = asn
	return ev
}

func checkAllowlist() Check {
	mk := func(n int) []model.Event {
		return nEvents(n, func(ev *model.Event) {
			ev.BlockedCode = "path_not_allowed"
			ev.Status = 403
			ev.Country = "DE"
			ev.ASN = 999
		})
	}
	ch := expect(runFresh(mk(5)), []Hit{{Rule: RuleAllow, Severity: SevMedium}}, false)
	if len(alertHits(runFresh(mk(4)))) != 0 {
		ch = fail(ch, "4 allowlist violations alerted")
	}
	return ch
}

func checkAuth() Check {
	mk := func(n int) []model.Event {
		return nEvents(n, func(ev *model.Event) {
			ev.Status = 401
			ev.Country = "DE"
			ev.ASN = 999
		})
	}
	ch := expect(runFresh(mk(10)), []Hit{{Rule: RuleAuth, Severity: SevMedium}}, false)
	if len(alertHits(runFresh(mk(9)))) != 0 {
		ch = fail(ch, "9 auth errors alerted")
	}
	return ch
}

func checkCanary() Check {
	at := func(t time.Time) model.Event {
		ev := baseEvent(t)
		ev.Kind = model.KindCanary
		ev.Status = 401
		ev.BlockedCode = "canary_used"
		ev.Country = "DE"
		ev.ASN = 999
		return ev
	}
	t0 := scenarioNow()
	short := runFresh([]model.Event{at(t0), at(t0.Add(30 * time.Minute))})
	full := runFresh([]model.Event{
		at(t0),
		at(t0.Add(30 * time.Minute)),
		at(t0.Add(30*time.Minute + time.Hour + time.Second)),
	})
	ch := expect(full, []Hit{{Rule: RuleCanary, Severity: SevCritical}, {Rule: RuleCanary, Severity: SevCritical}}, false)
	if len(alertHits(short)) != 1 {
		ch = fail(ch, "quiet hour opened a second alert")
	}
	return ch
}

func checkDisabled() Check {
	events := nEvents(101, func(ev *model.Event) {
		ev.BlockedCode = "key_disabled"
		ev.Status = 401
		ev.Country = "DE"
		ev.ASN = 999
		ev.IP = "198.51.100.20"
	})
	return expect(runFresh(events), []Hit{{Rule: RuleDisabled, Severity: SevHigh}}, false)
}

func checkLearning() Check {
	cost := int64(5*money.Dollar + 1)
	events := nEvents(101, func(ev *model.Event) {
		ev.Country = "DE"
		ev.ASN = 999
		ev.IP = "198.51.100.9"
		ev.CostMicro = &cost
	})
	return expect(runFresh(events), nil, false)
}

func checkSingleRule() Check {
	quiet := runLearned(nEvents(100, nil))
	ch := expect(runLearned(nEvents(110, nil)), []Hit{{Rule: RuleRate, Severity: SevMedium}}, false)
	if len(alertHits(quiet)) != 0 {
		ch = fail(ch, "100 requests in five minutes alerted")
	}
	return ch
}
