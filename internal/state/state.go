// Package state is the in-memory copy of keys, policies, and spend.
// The request path reads only this package. SQLite is updated first by the
// admin service; memory changes only after that commit succeeds.
package state

import (
	"crypto/rand"
	"net"
	"sync"
	"time"

	"github.com/kirank55/keman/internal/clientip"
	"github.com/kirank55/keman/internal/clock"
	"github.com/kirank55/keman/internal/keyfmt"
	"github.com/kirank55/keman/internal/model"
	"github.com/kirank55/keman/internal/money"
	"github.com/kirank55/keman/internal/pathmatch"
)

type State struct {
	mu         sync.Mutex
	clk        clock.Clock
	upstreams  map[string]model.Upstream
	upByName   map[string]string
	creds      map[string]model.Credential
	credByName map[string]string
	keys       map[string]model.VirtualKey
	policies   map[string]Policy
	spend      map[spendKey]spendVal
	open       map[string]int64
	keyRate    map[string]*window
	invalid    map[string]*window
	invalidRPM int
	failAfter  time.Duration
	failing    *time.Time
	adminHash  []byte
	dummy      []byte
}

type spendKey struct {
	id     string
	period string
}

type spendVal struct {
	micro int64
	dirty bool
}

type window struct {
	times []time.Time
}

// Policy is a virtual key's limits with the allowlists already parsed.
type Policy struct {
	model.Policy
	Paths     []pathmatch.Rule
	Models    map[string]struct{}
	CIDRs     []*net.IPNet
	Countries map[string]struct{}
}

func New(clk clock.Clock, invalidRPM int, failAfter time.Duration) *State {
	if clk == nil {
		clk = clock.System{}
	}
	if invalidRPM <= 0 {
		invalidRPM = 60
	}
	if failAfter <= 0 {
		failAfter = 60 * time.Second
	}
	dummy := make([]byte, 32)
	_, _ = rand.Read(dummy)
	return &State{
		clk:        clk,
		upstreams:  map[string]model.Upstream{},
		upByName:   map[string]string{},
		creds:      map[string]model.Credential{},
		credByName: map[string]string{},
		keys:       map[string]model.VirtualKey{},
		policies:   map[string]Policy{},
		spend:      map[spendKey]spendVal{},
		open:       map[string]int64{},
		keyRate:    map[string]*window{},
		invalid:    map[string]*window{},
		invalidRPM: invalidRPM,
		failAfter:  failAfter,
		dummy:      dummy,
	}
}

func (s *State) Now() time.Time { return s.clk.Now() }

func (s *State) SetAdminHash(h []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.adminHash = append([]byte(nil), h...)
}

func (s *State) AdminOK(token string) bool {
	sum := keyfmt.HashToken(token)
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.adminHash) != len(sum) {
		return false
	}
	var diff byte
	for i := range sum {
		diff |= sum[i] ^ s.adminHash[i]
	}
	return diff == 0
}

func (s *State) PutUpstream(u model.Upstream) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.upstreams[u.ID]; ok {
		delete(s.upByName, old.Name)
	}
	s.upstreams[u.ID] = u
	s.upByName[u.Name] = u.ID
}

func (s *State) Upstream(id string) (model.Upstream, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.upstreams[id]
	return u, ok
}

func (s *State) UpstreamByName(name string) (model.Upstream, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.upByName[name]
	if !ok {
		return model.Upstream{}, false
	}
	return s.upstreams[id], true
}

func (s *State) Upstreams() []model.Upstream {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.Upstream, 0, len(s.upstreams))
	for _, u := range s.upstreams {
		out = append(out, u)
	}
	return out
}

func (s *State) PutCredential(c model.Credential) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.creds[c.ID]; ok {
		delete(s.credByName, old.Name)
	}
	s.creds[c.ID] = c
	s.credByName[c.Name] = c.ID
}

func (s *State) Credential(id string) (model.Credential, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.creds[id]
	return c, ok
}

func (s *State) CredentialByName(name string) (model.Credential, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.credByName[name]
	if !ok {
		return model.Credential{}, false
	}
	return s.creds[id], true
}

func (s *State) Credentials() []model.Credential {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.Credential, 0, len(s.creds))
	for _, c := range s.creds {
		c.Plaintext = ""
		c.Ciphertext = nil
		c.Nonce = nil
		out = append(out, c)
	}
	return out
}

func (s *State) PutKey(k model.VirtualKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k.SecretHash = append([]byte(nil), k.SecretHash...)
	s.keys[k.ID] = k
}

func (s *State) Key(id string) (model.VirtualKey, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[id]
	if ok {
		k.SecretHash = append([]byte(nil), k.SecretHash...)
	}
	return k, ok
}

func (s *State) Keys() []model.VirtualKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.VirtualKey, 0, len(s.keys))
	for _, k := range s.keys {
		k.SecretHash = nil
		out = append(out, k)
	}
	return out
}

// Match reports whether id exists and the secret matches. Unknown ids still
// compare against a dummy hash.
func (s *State) Match(id, secret string) (model.VirtualKey, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[id]
	if !ok {
		keyfmt.MatchHash(secret, s.dummy, s.dummy)
		return model.VirtualKey{}, false
	}
	if !keyfmt.MatchHash(secret, k.SecretHash, s.dummy) {
		return model.VirtualKey{}, false
	}
	k.SecretHash = append([]byte(nil), k.SecretHash...)
	return k, true
}

func (s *State) PutPolicy(p Policy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policies[p.KeyID] = p
}

func (s *State) Policy(id string) (Policy, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.policies[id]
	return p, ok
}

func (s *State) Policies() []Policy {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Policy, 0, len(s.policies))
	for _, p := range s.policies {
		out = append(out, p)
	}
	return out
}

// AllowInvalid counts an authentication failure for this client IP.
func (s *State) AllowInvalid(ip string, now time.Time) (bool, time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w := s.invalid[ip]
	if w == nil {
		w = &window{}
		s.invalid[ip] = w
	}
	return w.allow(now, s.invalidRPM)
}

// AllowKey counts one request against the virtual key's per-minute limit.
// rpm <= 0 means unlimited.
func (s *State) AllowKey(id string, rpm int, now time.Time) (bool, time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rpm <= 0 {
		return true, 0
	}
	w := s.keyRate[id]
	if w == nil {
		w = &window{}
		s.keyRate[id] = w
	}
	return w.allow(now, rpm)
}

func (w *window) allow(now time.Time, limit int) (bool, time.Duration) {
	cutoff := now.Add(-time.Minute)
	i := 0
	for i < len(w.times) && !w.times[i].After(cutoff) {
		i++
	}
	w.times = w.times[i:]
	if len(w.times) >= limit {
		retry := w.times[0].Add(time.Minute).Sub(now)
		if retry < time.Second {
			retry = time.Second
		}
		return false, retry
	}
	w.times = append(w.times, now)
	return true, 0
}

func DayPeriod(t time.Time) string   { return "d:" + t.UTC().Format("2006-01-02") }
func MonthPeriod(t time.Time) string { return "m:" + t.UTC().Format("2006-01") }

// SpendDegraded is true when flushes have been failing long enough and the
// key has a spend cap.
func (s *State) SpendDegraded(keyID string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.policies[keyID]
	if !ok || (p.DailyCapMicro == nil && p.MonthlyCapMicro == nil) {
		return false
	}
	if s.failing == nil {
		return false
	}
	return now.Sub(*s.failing) >= s.failAfter
}

func (s *State) NoteFlush(ok bool, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ok {
		s.failing = nil
		return
	}
	if s.failing == nil {
		t := now
		s.failing = &t
	}
}

func (s *State) FlushFailing() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failing != nil
}

// Reserve holds amount against the key's caps. It does not hold anything
// when a cap would be exceeded.
func (s *State) Reserve(id string, amount int64, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if amount < 0 {
		amount = 0
	}
	p := s.policies[id]
	open := s.open[id]
	if p.DailyCapMicro != nil && exceedsCap(s.committed(id, DayPeriod(now)), open, amount, *p.DailyCapMicro) {
		return false
	}
	if p.MonthlyCapMicro != nil && exceedsCap(s.committed(id, MonthPeriod(now)), open, amount, *p.MonthlyCapMicro) {
		return false
	}
	s.open[id] = money.Add(open, amount)
	return true
}

func exceedsCap(committed, open, amount, cap int64) bool {
	return money.Add(money.Add(committed, open), amount) > cap
}

func (s *State) committed(id, period string) int64 {
	return s.spend[spendKey{id, period}].micro
}

// Reconcile replaces a reservation with the actual cost.
func (s *State) Reconcile(id string, reservation, actual int64, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.open[id] -= reservation
	if s.open[id] < 0 {
		s.open[id] = 0
	}
	if actual == 0 {
		return
	}
	s.add(id, DayPeriod(now), actual)
	s.add(id, MonthPeriod(now), actual)
}

// Release drops a reservation without charging it.
func (s *State) Release(id string, reservation int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.open[id] -= reservation
	if s.open[id] < 0 {
		s.open[id] = 0
	}
}

func (s *State) add(id, period string, micro int64) {
	k := spendKey{id, period}
	cur := s.spend[k]
	cur.micro = money.Add(cur.micro, micro)
	cur.dirty = true
	s.spend[k] = cur
}

func (s *State) LoadSpend(rows []model.SpendRow) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, row := range rows {
		s.spend[spendKey{row.KeyID, row.Period}] = spendVal{micro: row.Micro}
	}
}

// DirtySpend returns counters changed since the last successful flush.
func (s *State) DirtySpend() []model.SpendRow {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []model.SpendRow
	for k, v := range s.spend {
		if v.dirty {
			out = append(out, model.SpendRow{KeyID: k.id, Period: k.period, Micro: v.micro})
		}
	}
	return out
}

// AckSpend clears the dirty bit when the value has not moved since the snapshot.
func (s *State) AckSpend(rows []model.SpendRow) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, row := range rows {
		k := spendKey{row.KeyID, row.Period}
		cur := s.spend[k]
		if cur.micro == row.Micro {
			cur.dirty = false
			s.spend[k] = cur
		}
	}
}

func (s *State) SetDryRun(id string, armed bool, blocked int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[id]
	if !ok {
		return
	}
	k.DryRunArmed = armed
	k.DryRunBlocked = blocked
	s.keys[id] = k
}

// NetworkAllowed reports whether the client IP satisfies the policy.
// An empty allowlist allows every address. A country allowlist with no
// country (lookup miss) is denied.
func NetworkAllowed(p Policy, ip net.IP, country string) bool {
	if len(p.CIDRs) > 0 {
		if ip == nil || !clientipContains(p.CIDRs, ip) {
			return false
		}
	}
	if len(p.Countries) > 0 {
		if country == "" {
			return false
		}
		if _, ok := p.Countries[country]; !ok {
			return false
		}
	}
	return true
}

func clientipContains(nets []*net.IPNet, ip net.IP) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ParsePolicy turns stored allowlist strings into a Policy.
func ParsePolicy(p model.Policy) (Policy, error) {
	out := Policy{Policy: p, Models: map[string]struct{}{}, Countries: map[string]struct{}{}}
	var err error
	out.Paths, err = pathmatch.ParseList(joinLines(p.PathAllowlist))
	if err != nil {
		return Policy{}, err
	}
	out.CIDRs, err = clientip.ParseCIDRs(p.CIDRAllowlist)
	if err != nil {
		return Policy{}, err
	}
	for _, m := range p.ModelAllowlist {
		if m != "" {
			out.Models[m] = struct{}{}
		}
	}
	for _, c := range p.CountryAllowlist {
		if c != "" {
			out.Countries[c] = struct{}{}
		}
	}
	if out.Mode == "" {
		out.Mode = model.ModeAlertOnly
	}
	return out, nil
}

func joinLines(lines []string) string {
	s := ""
	for i, line := range lines {
		if i > 0 {
			s += "\n"
		}
		s += line
	}
	return s
}
