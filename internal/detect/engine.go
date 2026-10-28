// Package detect runs behavior rules off the request path.
// Inline blocking stays in the proxy. This package only records, alerts,
// and decides whether auto-disable should flip a key.
package detect

import (
	"bytes"
	"encoding/json"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/kirank55/keman/internal/clock"
	"github.com/kirank55/keman/internal/model"
	"github.com/kirank55/keman/internal/money"
)

const (
	RuleCanary   = "canary_used"
	RuleDisabled = "disabled_key_used"
	RuleSpend    = "spend_spike"
	RuleRate     = "rate_spike"
	RuleCountry  = "new_country"
	RuleAllow    = "allowlist_violations"
	RuleAuth     = "upstream_auth_burst"
	RuleASN      = "new_asn"

	SevCritical = "critical"
	SevHigh     = "high"
	SevMedium   = "medium"
	SevLow      = "low"
)

type Config struct {
	SpendFloorMicro  int64
	SpendMultiplier  int
	RateFloor        int
	RateMultiplier   int
	AllowlistCount   int
	AllowlistWindow  time.Duration
	AuthBurst        int
	AuthWindow       time.Duration
	LearningRequests int
	LearningWindow   time.Duration
	IncidentQuiet    time.Duration
	AutoCount        int
	AutoDistinct     int
	AutoWindow       time.Duration
	BaselineWindow   time.Duration
}

func DefaultConfig() Config {
	return Config{
		SpendFloorMicro:  5 * money.Dollar,
		SpendMultiplier:  5,
		RateFloor:        100,
		RateMultiplier:   10,
		AllowlistCount:   5,
		AllowlistWindow:  5 * time.Minute,
		AuthBurst:        10,
		AuthWindow:       5 * time.Minute,
		LearningRequests: 500,
		LearningWindow:   7 * 24 * time.Hour,
		IncidentQuiet:    time.Hour,
		AutoCount:        3,
		AutoDistinct:     2,
		AutoWindow:       15 * time.Minute,
		BaselineWindow:   7 * 24 * time.Hour,
	}
}

type Outcome struct {
	Detections []model.Detection
	Alerts     []model.Alert
	Incidents  []IncidentUpdate
	DisableKey bool
	DryRunTrip bool
	WouldBlock bool
	Baseline   model.Baseline
}

type IncidentUpdate struct {
	KeyID  string
	Rule   string
	Opened time.Time
	Last   time.Time
	IsNew  bool
}

type Engine struct {
	mu   sync.Mutex
	clk  clock.Clock
	cfg  Config
	keys map[string]*keyState
}

type incident struct {
	opened time.Time
	last   time.Time
}

type keyState struct {
	first      time.Time
	count      int
	countries  map[string]time.Time
	asns       map[int]time.Time
	counts     map[int64]int
	spend      map[int64]int64
	blocks     []time.Time
	auths      []time.Time
	dets       []model.Detection
	incidents  map[string]incident
	dryArmed   bool
	dryBlocked int
	autoFired  bool
	paused     time.Time
}

func New(clk clock.Clock, cfg Config) *Engine {
	if clk == nil {
		clk = clock.System{}
	}
	if cfg.SpendMultiplier == 0 {
		cfg = DefaultConfig()
	}
	return &Engine{clk: clk, cfg: cfg, keys: map[string]*keyState{}}
}

func (e *Engine) key(id string) *keyState {
	st := e.keys[id]
	if st == nil {
		st = &keyState{
			countries: map[string]time.Time{},
			asns:      map[int]time.Time{},
			counts:    map[int64]int{},
			spend:     map[int64]int64{},
			incidents: map[string]incident{},
		}
		e.keys[id] = st
	}
	return st
}

// LoadBaseline installs persisted identity data. Buckets are rebuilt with Restore.
func (e *Engine) LoadBaseline(b model.Baseline) {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := e.key(b.KeyID)
	st.first = b.FirstSeen
	st.count = b.RequestCount
	if b.Countries != nil {
		st.countries = b.Countries
	}
	if b.ASNs != nil {
		st.asns = b.ASNs
	}
	st.dryArmed = b.DryRunArmed
	st.dryBlocked = b.DryRunBlocked
}

// LoadDetection primes the auto-disable window from storage.
func (e *Engine) LoadDetection(d model.Detection) {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := e.key(d.KeyID)
	st.dets = append(st.dets, d)
}

// LoadIncident restores an open incident so a restart does not send the alert again.
func (e *Engine) LoadIncident(keyID, rule string, opened, last time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := e.key(keyID)
	st.incidents[rule] = incident{opened: opened, last: last}
}

// NoteStatus tells the engine the key was disabled or re-enabled.
func (e *Engine) NoteStatus(id, status string, pausedUntil time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := e.key(id)
	st.autoFired = status == model.StatusDisabled || status == model.StatusRevoked
	st.paused = pausedUntil
	if status == model.StatusActive {
		st.autoFired = false
	}
}

// Restore rebuilds rolling windows from a stored event without alerting.
func (e *Engine) Restore(ev model.Event) {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := e.key(ev.KeyID)
	e.bumpWindows(st, ev)
}

// Observe applies one live event.
func (e *Engine) Observe(ev model.Event) Outcome {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := e.key(ev.KeyID)
	if !ev.PausedUntil.IsZero() && ev.PausedUntil.After(st.paused) {
		st.paused = ev.PausedUntil
	}
	if st.first.IsZero() {
		st.first = ev.Time
	}
	st.count++
	e.bumpWindows(st, ev)
	e.prune(st, ev.Time)

	var out Outcome
	switch {
	case ev.Kind == model.KindCanary:
		e.add(&out, st, ev, RuleCanary, SevCritical, map[string]any{"count": 1})
	case ev.BlockedCode == "key_disabled" || ev.BlockedCode == "key_revoked" || ev.BlockedCode == "key_expired":
		e.add(&out, st, ev, RuleDisabled, SevHigh, map[string]any{
			"status": ev.BlockedCode,
			"ip":     ev.IP,
		})
	default:
		e.rules(&out, st, ev)
		e.auto(&out, st, ev)
	}
	out.Baseline = e.snapshot(ev.KeyID, st)
	return out
}

// Replay runs Observe on each event in order.
func (e *Engine) Replay(events []model.Event) []Outcome {
	out := make([]Outcome, 0, len(events))
	for _, ev := range events {
		out = append(out, e.Observe(ev))
	}
	return out
}

func (e *Engine) bumpWindows(st *keyState, ev model.Event) {
	st.counts[bucket5(ev.Time)]++
	if ev.CostMicro != nil {
		st.spend[bucketHour(ev.Time)] += *ev.CostMicro
	}
	if isAllowlist(ev.BlockedCode) {
		st.blocks = append(st.blocks, ev.Time)
	}
	if ev.BlockedCode == "" && (ev.Status == 401 || ev.Status == 403) {
		st.auths = append(st.auths, ev.Time)
	}
}

func (e *Engine) prune(st *keyState, now time.Time) {
	old := bucket5(now.Add(-e.cfg.BaselineWindow - time.Hour))
	for b := range st.counts {
		if b < old {
			delete(st.counts, b)
		}
	}
	hold := bucketHour(now.Add(-e.cfg.BaselineWindow - time.Hour))
	for b := range st.spend {
		if b < hold {
			delete(st.spend, b)
		}
	}
	st.blocks = within(st.blocks, now, e.cfg.AllowlistWindow)
	st.auths = within(st.auths, now, e.cfg.AuthWindow)
	cut := now.Add(-e.cfg.AutoWindow)
	kept := st.dets[:0]
	for _, d := range st.dets {
		if !d.Time.Before(cut) {
			kept = append(kept, d)
		}
	}
	st.dets = kept
}

func (e *Engine) rules(out *Outcome, st *keyState, ev model.Event) {
	learning := st.count <= e.cfg.LearningRequests && ev.Time.Sub(st.first) < e.cfg.LearningWindow

	if isAllowlist(ev.BlockedCode) {
		n := len(within(st.blocks, ev.Time, e.cfg.AllowlistWindow))
		if n >= e.cfg.AllowlistCount {
			e.add(out, st, ev, RuleAllow, SevMedium, map[string]any{"count": n, "window_seconds": int(e.cfg.AllowlistWindow.Seconds())})
		}
	}

	if !learning {
		count := st.counts[bucket5(ev.Time)]
		med := median(e.series5(st, ev.Time))
		thresh := e.cfg.RateFloor
		if scaled := e.cfg.RateMultiplier * med; scaled > thresh {
			thresh = scaled
		}
		if count > thresh {
			e.add(out, st, ev, RuleRate, SevMedium, map[string]any{
				"count": count, "median": med, "threshold": thresh,
			})
		}

		hour := st.spend[bucketHour(ev.Time)]
		p := p95(e.seriesHour(st, ev.Time))
		sthresh := e.cfg.SpendFloorMicro
		if scaled := int64(e.cfg.SpendMultiplier) * p; scaled > sthresh {
			sthresh = scaled
		}
		if hour > sthresh {
			e.add(out, st, ev, RuleSpend, SevHigh, map[string]any{
				"hour_microusd": hour, "p95_microusd": p, "threshold_microusd": sthresh, "model": ev.Model,
			})
		}

		if ev.Country != "" {
			if _, seen := st.countries[ev.Country]; !seen {
				e.add(out, st, ev, RuleCountry, SevMedium, map[string]any{"country": ev.Country})
			}
		}
		if ev.ASN != 0 {
			if _, seen := st.asns[ev.ASN]; !seen {
				e.add(out, st, ev, RuleASN, SevLow, map[string]any{"asn": ev.ASN})
			}
		}
	}

	if ev.Country != "" {
		if _, seen := st.countries[ev.Country]; !seen {
			st.countries[ev.Country] = ev.Time
		}
	}
	if ev.ASN != 0 {
		if _, seen := st.asns[ev.ASN]; !seen {
			st.asns[ev.ASN] = ev.Time
		}
	}

	if ev.BlockedCode == "" && (ev.Status == 401 || ev.Status == 403) {
		n := len(within(st.auths, ev.Time, e.cfg.AuthWindow))
		if n >= e.cfg.AuthBurst {
			e.add(out, st, ev, RuleAuth, SevMedium, map[string]any{"count": n})
		}
	}
}

func (e *Engine) add(out *Outcome, st *keyState, ev model.Event, rule, sev string, evidence map[string]any) {
	d := model.Detection{
		Time: ev.Time, KeyID: ev.KeyID, Rule: rule, Severity: sev, Evidence: evidence,
	}
	st.dets = append(st.dets, d)
	out.Detections = append(out.Detections, d)
	isNew, opened := e.incident(st, rule, ev.Time)
	out.Incidents = append(out.Incidents, IncidentUpdate{
		KeyID: ev.KeyID, Rule: rule, Opened: opened, Last: ev.Time, IsNew: isNew,
	})
	if !isNew {
		return
	}
	base := map[string]any{
		"request_count": st.count,
		"countries":     len(st.countries),
		"asns":          len(st.asns),
	}
	observed := map[string]any{
		"ip": ev.IP, "country": ev.Country, "asn": ev.ASN, "model": ev.Model, "operation": ev.Operation,
	}
	for k, v := range evidence {
		observed[k] = v
	}
	out.Alerts = append(out.Alerts, model.Alert{
		Rule: rule, Severity: sev, KeyID: ev.KeyID,
		Evidence: evidence, Baseline: base, Observed: observed,
		Commands: Commands(ev.KeyID, ev.IP, ev.Country),
		FiredAt:  ev.Time,
	})
}

func (e *Engine) incident(st *keyState, rule string, now time.Time) (isNew bool, opened time.Time) {
	inc, ok := st.incidents[rule]
	if ok && now.Sub(inc.last) < e.cfg.IncidentQuiet {
		inc.last = now
		st.incidents[rule] = inc
		return false, inc.opened
	}
	st.incidents[rule] = incident{opened: now, last: now}
	return true, now
}

func (e *Engine) auto(out *Outcome, st *keyState, ev model.Event) {
	if ev.Mode != model.ModeDryRun && ev.Mode != model.ModeAutoDisable {
		return
	}
	if st.dryArmed && ev.Mode == model.ModeDryRun {
		out.WouldBlock = true
		st.dryBlocked++
	}
	if !tripped(st, e.cfg, ev.Time) {
		return
	}
	if !st.paused.IsZero() && ev.Time.Before(st.paused) {
		return
	}
	switch ev.Mode {
	case model.ModeAutoDisable:
		if !st.autoFired {
			st.autoFired = true
			out.DisableKey = true
		}
	case model.ModeDryRun:
		if !st.dryArmed {
			st.dryArmed = true
			out.DryRunTrip = true
		}
	}
}

func tripped(st *keyState, cfg Config, now time.Time) bool {
	cut := now.Add(-cfg.AutoWindow)
	rules := map[string]struct{}{}
	n := 0
	for _, d := range st.dets {
		if d.Time.Before(cut) || !counts(d.Rule) || rank(d.Severity) < rank(SevMedium) {
			continue
		}
		n++
		rules[d.Rule] = struct{}{}
	}
	return n >= cfg.AutoCount && len(rules) >= cfg.AutoDistinct
}

func counts(rule string) bool {
	switch rule {
	case RuleSpend, RuleRate, RuleCountry, RuleAllow:
		return true
	default:
		return false
	}
}

func rank(sev string) int {
	switch sev {
	case SevCritical:
		return 4
	case SevHigh:
		return 3
	case SevMedium:
		return 2
	default:
		return 1
	}
}

func (e *Engine) snapshot(id string, st *keyState) model.Baseline {
	countries := make(map[string]time.Time, len(st.countries))
	for k, v := range st.countries {
		countries[k] = v
	}
	asns := make(map[int]time.Time, len(st.asns))
	for k, v := range st.asns {
		asns[k] = v
	}
	return model.Baseline{
		KeyID: id, FirstSeen: st.first, RequestCount: st.count,
		Countries: countries, ASNs: asns,
		DryRunArmed: st.dryArmed, DryRunBlocked: st.dryBlocked,
	}
}

func (e *Engine) series5(st *keyState, now time.Time) []int {
	end := bucket5(now)
	start := bucket5(now.Add(-e.cfg.BaselineWindow))
	vals := make([]int, 0, int(e.cfg.BaselineWindow/time.Minute/5)+1)
	for b := start; b <= end; b += 300 {
		vals = append(vals, st.counts[b])
	}
	return vals
}

func (e *Engine) seriesHour(st *keyState, now time.Time) []int64 {
	end := bucketHour(now)
	start := bucketHour(now.Add(-e.cfg.BaselineWindow))
	var vals []int64
	for b := start; b <= end; b += 3600 {
		vals = append(vals, st.spend[b])
	}
	return vals
}

func bucket5(t time.Time) int64    { return t.UTC().Unix() / 300 * 300 }
func bucketHour(t time.Time) int64 { return t.UTC().Unix() / 3600 * 3600 }

func median(vals []int) int {
	if len(vals) == 0 {
		return 0
	}
	sort.Ints(vals)
	return vals[len(vals)/2]
}

func p95(vals []int64) int64 {
	if len(vals) == 0 {
		return 0
	}
	sort.Slice(vals, func(i, j int) bool { return vals[i] < vals[j] })
	idx := (len(vals)*95+99)/100 - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(vals) {
		idx = len(vals) - 1
	}
	return vals[idx]
}

func within(ts []time.Time, now time.Time, window time.Duration) []time.Time {
	cut := now.Add(-window)
	out := make([]time.Time, 0, len(ts))
	for _, t := range ts {
		if !t.Before(cut) {
			out = append(out, t)
		}
	}
	return out
}

func isAllowlist(code string) bool {
	switch code {
	case "path_not_allowed", "model_not_allowed", "network_not_allowed":
		return true
	default:
		return false
	}
}

// Commands are the lines an alert shows an operator.
func Commands(keyID, ip, country string) []string {
	cmds := []string{"keman key disable " + keyID}
	if ip != "" {
		cmds = append(cmds, "keman policy set "+keyID+" --cidr "+hostCIDR(ip))
	}
	if country != "" {
		cmds = append(cmds, "keman policy set "+keyID+" --country "+country)
	}
	cmds = append(cmds, "keman policy set "+keyID+" --daily-usd 1")
	return cmds
}

func hostCIDR(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed != nil && parsed.To4() == nil {
		return ip + "/128"
	}
	return ip + "/32"
}

type fixture struct {
	Time        time.Time `json:"time"`
	KeyID       string    `json:"key_id"`
	Kind        string    `json:"kind"`
	IP          string    `json:"ip"`
	Country     string    `json:"country"`
	ASN         int       `json:"asn"`
	Operation   string    `json:"operation"`
	Status      int       `json:"status"`
	CostMicro   *int64    `json:"cost_micro"`
	Model       string    `json:"model"`
	BlockedCode string    `json:"blocked_code"`
	Mode        string    `json:"mode"`
}

// LoadFixture reads a JSON array or JSONL of past events.
func LoadFixture(data []byte) ([]model.Event, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, nil
	}
	var rows []fixture
	if data[0] == '[' {
		if err := json.Unmarshal(data, &rows); err != nil {
			return nil, err
		}
	} else {
		dec := json.NewDecoder(bytes.NewReader(data))
		for dec.More() {
			var row fixture
			if err := dec.Decode(&row); err != nil {
				return nil, err
			}
			rows = append(rows, row)
		}
	}
	out := make([]model.Event, 0, len(rows))
	for _, row := range rows {
		kind := row.Kind
		if kind == "" {
			kind = model.KindStandard
		}
		mode := row.Mode
		if mode == "" {
			mode = model.ModeAlertOnly
		}
		out = append(out, model.Event{
			Time: row.Time, KeyID: row.KeyID, Kind: kind, IP: row.IP, Country: row.Country,
			ASN: row.ASN, Operation: row.Operation, Status: row.Status, CostMicro: row.CostMicro,
			Model: row.Model, BlockedCode: row.BlockedCode, Mode: mode,
		})
	}
	return out, nil
}
