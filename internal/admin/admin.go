// Package admin is the management surface: SQLite first, then memory.
package admin

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/kirank55/keman/internal/apierr"
	"github.com/kirank55/keman/internal/clock"
	"github.com/kirank55/keman/internal/cryptoenc"
	"github.com/kirank55/keman/internal/detect"
	"github.com/kirank55/keman/internal/exposure"
	"github.com/kirank55/keman/internal/headers"
	"github.com/kirank55/keman/internal/keyfmt"
	"github.com/kirank55/keman/internal/model"
	"github.com/kirank55/keman/internal/profile"
	"github.com/kirank55/keman/internal/state"
	"github.com/kirank55/keman/internal/store"
)

// OpError is a failure the admin API can show to a caller.
type OpError struct {
	Status  int
	Code    string
	Message string
	Report  *DryRunReport
}

func (e *OpError) Error() string { return e.Message }

type DryRunReport struct {
	From               time.Time  `json:"from"`
	To                 time.Time  `json:"to"`
	WouldDisable       bool       `json:"would_disable"`
	WouldDisableAt     *time.Time `json:"would_disable_at,omitempty"`
	RequestsWouldBlock int        `json:"requests_would_block"`
	Detections         int        `json:"detections"`
}

type Service struct {
	Store      *store.Store
	State      *state.State
	Box        *cryptoenc.Box
	Clock      clock.Clock
	Rules      detect.Config
	GeoCountry bool
	// DefaultTTL is the expiry given to a new standard key that names none.
	// Zero means new keys never expire unless asked.
	DefaultTTL time.Duration
	OnStatus   func(id, status string, paused time.Time)
	OnSecret   func(string)
	Log        *slog.Logger
}

func (s *Service) noteSecret(secret string) {
	if s.OnSecret != nil && secret != "" {
		s.OnSecret(secret)
	}
}

func (s *Service) now() time.Time {
	if s.Clock != nil {
		return s.Clock.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Service) audit(ctx context.Context, actor, action, target, before, after, ip string) {
	err := s.Store.InsertAudit(ctx, model.AuditEntry{
		Time: s.now(), Actor: actor, Action: action, Target: target, Before: before, After: after, IP: ip,
	})
	if err != nil && s.Log != nil {
		s.Log.Info("audit write failed", "action", action, "target", target)
	}
}

func (s *Service) CreateUpstream(ctx context.Context, u model.Upstream, actor, ip string) (model.Upstream, error) {
	u.Name = strings.TrimSpace(u.Name)
	if u.Name == "" {
		return model.Upstream{}, &OpError{Status: 400, Code: "invalid", Message: "Upstream name is required."}
	}
	if u.Protocol == "" {
		u.Protocol = model.ProtocolHTTP
	}
	if u.Protocol != model.ProtocolHTTP {
		return model.Upstream{}, &OpError{Status: 400, Code: "invalid", Message: "The beta only supports protocol http."}
	}
	if !profile.Valid(u.Profile) {
		return model.Upstream{}, &OpError{Status: 400, Code: "invalid", Message: "Profile must be openai, anthropic, or generic."}
	}
	if !validHost(u.Host) {
		return model.Upstream{}, &OpError{Status: 400, Code: "invalid", Message: "Upstream host is invalid."}
	}
	if u.Port < 1 || u.Port > 65535 {
		return model.Upstream{}, &OpError{Status: 400, Code: "invalid", Message: "Upstream port is invalid."}
	}
	if u.Profile == profile.Generic && len(u.PathAllowlist) == 0 {
		return model.Upstream{}, &OpError{Status: 400, Code: "invalid", Message: "A generic upstream needs a path allowlist."}
	}
	if _, err := state.ParsePolicy(model.Policy{PathAllowlist: u.PathAllowlist}); err != nil && len(u.PathAllowlist) > 0 {
		return model.Upstream{}, &OpError{Status: 400, Code: "invalid", Message: err.Error()}
	}
	id, err := keyfmt.NewID("up", 12)
	if err != nil {
		return model.Upstream{}, err
	}
	u.ID = id
	u.CreatedAt = s.now()
	if err := s.Store.InsertUpstream(ctx, u); err != nil {
		return model.Upstream{}, conflict(err)
	}
	s.State.PutUpstream(u)
	s.audit(ctx, actor, "upstream.create", u.ID, "", u.Name, ip)
	return u, nil
}

func (s *Service) CreateCredential(ctx context.Context, c model.Credential, secret, actor, ip string) (model.Credential, error) {
	c.Name = strings.TrimSpace(c.Name)
	if c.Name == "" {
		return model.Credential{}, &OpError{Status: 400, Code: "invalid", Message: "Credential name is required."}
	}
	if secret == "" {
		return model.Credential{}, &OpError{Status: 400, Code: "invalid", Message: "Credential secret is required."}
	}
	if _, ok := s.State.Upstream(c.UpstreamID); !ok {
		return model.Credential{}, &OpError{Status: 404, Code: "not_found", Message: "Upstream not found."}
	}
	if c.AuthStyle == "" {
		c.AuthStyle = model.AuthHeader
	}
	if err := checkAuth(c); err != nil {
		return model.Credential{}, err
	}
	id, err := keyfmt.NewID("cred", 12)
	if err != nil {
		return model.Credential{}, err
	}
	nonce, ct, err := s.Box.Encrypt([]byte(id), []byte(secret))
	if err != nil {
		return model.Credential{}, err
	}
	now := s.now()
	c.ID = id
	c.Ciphertext = ct
	c.Nonce = nonce
	c.KeyVersion = 1
	c.Last4 = last4(secret)
	c.Plaintext = secret
	c.CreatedAt = now
	c.UpdatedAt = now
	stored := c
	stored.Plaintext = ""
	if err := s.Store.InsertCredential(ctx, stored); err != nil {
		return model.Credential{}, conflict(err)
	}
	s.State.PutCredential(c)
	s.noteSecret(secret)
	s.audit(ctx, actor, "credential.create", c.ID, "", `{"last4":"`+c.Last4+`"}`, ip)
	c.Plaintext = ""
	c.Ciphertext = nil
	c.Nonce = nil
	return c, nil
}

func (s *Service) RotateCredential(ctx context.Context, id, secret, actor, ip string) (model.Credential, error) {
	if secret == "" {
		return model.Credential{}, &OpError{Status: 400, Code: "invalid", Message: "Credential secret is required."}
	}
	cur, ok := s.State.Credential(id)
	if !ok {
		return model.Credential{}, &OpError{Status: 404, Code: "not_found", Message: "Credential not found."}
	}
	nonce, ct, err := s.Box.Encrypt([]byte(id), []byte(secret))
	if err != nil {
		return model.Credential{}, err
	}
	now := s.now()
	version := cur.KeyVersion + 1
	if err := s.Store.UpdateCredentialSecret(ctx, id, ct, nonce, version, last4(secret), now); err != nil {
		return model.Credential{}, err
	}
	cur.Ciphertext = ct
	cur.Nonce = nonce
	cur.KeyVersion = version
	cur.Last4 = last4(secret)
	cur.Plaintext = secret
	cur.UpdatedAt = now
	s.State.PutCredential(cur)
	s.noteSecret(secret)
	s.audit(ctx, actor, "credential.rotate", id, "", `{"last4":"`+cur.Last4+`"}`, ip)
	cur.Plaintext = ""
	cur.Ciphertext = nil
	cur.Nonce = nil
	return cur, nil
}

// CreateKey issues a virtual key. A standard key with no expiry gets
// DefaultTTL unless noExpiry is set. Canary keys never expire by default:
// a decoy is meant to sit where it was planted.
func (s *Service) CreateKey(ctx context.Context, credentialID, name, kind string, expires *time.Time, noExpiry bool, actor, ip string) (token string, key model.VirtualKey, err error) {
	if _, ok := s.State.Credential(credentialID); !ok {
		return "", model.VirtualKey{}, &OpError{Status: 404, Code: "not_found", Message: "Credential not found."}
	}
	if kind == "" {
		kind = model.KindStandard
	}
	if kind != model.KindStandard && kind != model.KindCanary {
		return "", model.VirtualKey{}, &OpError{Status: 400, Code: "invalid", Message: "Kind must be standard or canary."}
	}
	if expires != nil && noExpiry {
		return "", model.VirtualKey{}, &OpError{Status: 400, Code: "invalid", Message: "Set an expiry or no_expiry, not both."}
	}
	if expires != nil && !expires.After(s.now()) {
		return "", model.VirtualKey{}, &OpError{Status: 400, Code: "invalid", Message: "The expiry must be in the future."}
	}
	if expires == nil && !noExpiry && kind == model.KindStandard && s.DefaultTTL > 0 {
		at := s.now().Add(s.DefaultTTL).Truncate(time.Second)
		expires = &at
	}
	id, secret, full, err := keyfmt.Generate()
	if err != nil {
		return "", model.VirtualKey{}, err
	}
	key = model.VirtualKey{
		ID: id, CredentialID: credentialID, Name: name, SecretHash: keyfmt.Hash(secret),
		Kind: kind, Status: model.StatusActive, ExpiresAt: expires, CreatedAt: s.now(),
	}
	if err := s.Store.InsertKey(ctx, key); err != nil {
		return "", model.VirtualKey{}, err
	}
	s.State.PutKey(key)
	s.audit(ctx, actor, "key.create", id, "", kind, ip)
	key.SecretHash = nil
	return full, key, nil
}

func (s *Service) SetStatus(ctx context.Context, id, status, actor, ip string) (model.VirtualKey, error) {
	key, ok := s.State.Key(id)
	if !ok {
		return model.VirtualKey{}, &OpError{Status: 404, Code: "not_found", Message: "Virtual key not found."}
	}
	if key.Status == model.StatusRevoked && status != model.StatusRevoked {
		return model.VirtualKey{}, &OpError{Status: 409, Code: "key_revoked", Message: "A revoked virtual key cannot be changed."}
	}
	var paused *time.Time
	if status == model.StatusActive && key.Status == model.StatusDisabled {
		until := s.now().Add(time.Hour)
		paused = &until
	} else {
		paused = key.PausedUntil
	}
	if status == model.StatusRevoked || status == model.StatusDisabled {
		paused = key.PausedUntil
	}
	before := key.Status
	if err := s.Store.UpdateKeyStatus(ctx, id, status, paused); err != nil {
		return model.VirtualKey{}, err
	}
	key.Status = status
	key.PausedUntil = paused
	key.SecretHash = nil
	full := key
	if cur, ok := s.State.Key(id); ok {
		full.SecretHash = cur.SecretHash
	}
	full.Status = status
	full.PausedUntil = paused
	s.State.PutKey(full)
	var pauseAt time.Time
	if paused != nil {
		pauseAt = *paused
	}
	if s.OnStatus != nil {
		s.OnStatus(id, status, pauseAt)
	}
	s.audit(ctx, actor, "key."+status, id, before, status, ip)
	full.SecretHash = nil
	return full, nil
}

// SetExpiry changes when a key stops working. nil means never.
func (s *Service) SetExpiry(ctx context.Context, id string, expires *time.Time, actor, ip string) (model.VirtualKey, error) {
	key, ok := s.State.Key(id)
	if !ok {
		return model.VirtualKey{}, &OpError{Status: 404, Code: "not_found", Message: "Virtual key not found."}
	}
	if key.Status == model.StatusRevoked {
		return model.VirtualKey{}, &OpError{Status: 409, Code: "key_revoked", Message: "A revoked virtual key cannot be changed."}
	}
	if expires != nil {
		at := expires.UTC()
		expires = &at
	}
	if err := s.Store.UpdateKeyLifecycle(ctx, id, key.Name, expires); err != nil {
		return model.VirtualKey{}, conflict(err)
	}
	before := expiryText(key.ExpiresAt)
	key.ExpiresAt = expires
	s.State.PutKey(key)
	s.audit(ctx, actor, "key.expiry", id, before, expiryText(expires), ip)
	key.SecretHash = nil
	return key, nil
}

// RotatedSuffix is added to the name of a key that a rotation replaced.
const RotatedSuffix = " (rotated)"

// Rotated is the result of RotateKey. Token is the new key's secret.
type Rotated struct {
	Token string
	New   model.VirtualKey
	Old   model.VirtualKey
}

// RotateKey issues a replacement for id with the same credential, name, kind
// and policy. The old key keeps working for grace, then expires; a zero grace
// revokes it now. The old key is renamed "<name> (rotated)" so names stay unique.
func (s *Service) RotateKey(ctx context.Context, id string, grace time.Duration, actor, ip string) (Rotated, error) {
	old, ok := s.State.Key(id)
	if !ok {
		return Rotated{}, &OpError{Status: 404, Code: "not_found", Message: "Virtual key not found."}
	}
	if old.Status == model.StatusRevoked {
		return Rotated{}, &OpError{Status: 409, Code: "key_revoked", Message: "A revoked virtual key cannot be rotated."}
	}
	if grace < 0 {
		return Rotated{}, &OpError{Status: 400, Code: "invalid", Message: "The grace period cannot be negative."}
	}
	now := s.now()
	var expires *time.Time
	if old.ExpiresAt != nil || s.DefaultTTL > 0 {
		ttl := s.DefaultTTL
		if old.ExpiresAt != nil && old.ExpiresAt.After(old.CreatedAt) {
			ttl = old.ExpiresAt.Sub(old.CreatedAt)
		}
		if ttl > 0 && old.Kind == model.KindStandard {
			at := now.Add(ttl).Truncate(time.Second)
			expires = &at
		}
	}
	token, fresh, err := s.CreateKey(ctx, old.CredentialID, old.Name, old.Kind, expires, expires == nil, actor, ip)
	if err != nil {
		return Rotated{}, err
	}
	if p, ok := s.State.Policy(id); ok {
		cp := p.Policy
		cp.KeyID = fresh.ID
		cp.UpdatedAt = now
		parsed, err := state.ParsePolicy(cp)
		if err == nil {
			err = s.Store.UpsertPolicy(ctx, cp)
		}
		if err != nil {
			return Rotated{}, err
		}
		s.State.PutPolicy(parsed)
	}
	oldName := old.Name
	if oldName == "" {
		oldName = old.ID
	}
	oldName += RotatedSuffix
	if grace == 0 {
		if err := s.Store.UpdateKeyLifecycle(ctx, id, oldName, old.ExpiresAt); err != nil {
			return Rotated{}, err
		}
		cur, _ := s.State.Key(id)
		cur.Name = oldName
		s.State.PutKey(cur)
		revoked, err := s.SetStatus(ctx, id, model.StatusRevoked, actor, ip)
		if err != nil {
			return Rotated{}, err
		}
		s.audit(ctx, actor, "key.rotate", id, "", fresh.ID, ip)
		return Rotated{Token: token, New: fresh, Old: revoked}, nil
	}
	until := now.Add(grace).Truncate(time.Second)
	if old.ExpiresAt != nil && old.ExpiresAt.Before(until) {
		until = *old.ExpiresAt
	}
	if err := s.Store.UpdateKeyLifecycle(ctx, id, oldName, &until); err != nil {
		return Rotated{}, err
	}
	old.Name = oldName
	old.ExpiresAt = &until
	s.State.PutKey(old)
	s.audit(ctx, actor, "key.rotate", id, "", fresh.ID, ip)
	old.SecretHash = nil
	return Rotated{Token: token, New: fresh, Old: old}, nil
}

func expiryText(t *time.Time) string {
	if t == nil {
		return "never"
	}
	return t.UTC().Format(time.RFC3339)
}

type PolicyInput struct {
	Mode            string   `json:"mode"`
	RPM             *int     `json:"rpm"`
	DailyCapMicro   *int64   `json:"daily_cap_microusd"`
	MonthlyCapMicro *int64   `json:"monthly_cap_microusd"`
	Paths           []string `json:"paths"`
	Models          []string `json:"models"`
	CIDRs           []string `json:"cidrs"`
	Countries       []string `json:"countries"`
	Confirm         bool     `json:"confirm"`
}

func (s *Service) SetPolicy(ctx context.Context, keyID string, in PolicyInput, actor, ip string) (state.Policy, *DryRunReport, error) {
	key, ok := s.State.Key(keyID)
	if !ok {
		return state.Policy{}, nil, &OpError{Status: 404, Code: "not_found", Message: "Virtual key not found."}
	}
	cred, ok := s.State.Credential(key.CredentialID)
	if !ok {
		return state.Policy{}, nil, &OpError{Status: 404, Code: "not_found", Message: "Credential not found."}
	}
	up, ok := s.State.Upstream(cred.UpstreamID)
	if !ok {
		return state.Policy{}, nil, &OpError{Status: 404, Code: "not_found", Message: "Upstream not found."}
	}
	if in.Mode == "" {
		in.Mode = model.ModeAlertOnly
	}
	if in.Mode != model.ModeAlertOnly && in.Mode != model.ModeDryRun && in.Mode != model.ModeAutoDisable {
		return state.Policy{}, nil, &OpError{Status: 400, Code: "invalid", Message: "Mode must be alert_only, dry_run, or auto_disable."}
	}
	if !profile.IsLLM(up.Profile) && (len(in.Models) > 0 || in.DailyCapMicro != nil || in.MonthlyCapMicro != nil) {
		return state.Policy{}, nil, &OpError{Status: 400, Code: "invalid", Message: "Model allowlists and spend caps are only for OpenAI and Anthropic profiles."}
	}
	if in.RPM != nil && *in.RPM <= 0 {
		return state.Policy{}, nil, &OpError{Status: 400, Code: "invalid", Message: "rpm must be greater than zero."}
	}
	for i, c := range in.Countries {
		in.Countries[i] = strings.ToUpper(strings.TrimSpace(c))
	}
	if len(in.Countries) > 0 && !s.GeoCountry {
		return state.Policy{}, nil, &OpError{Status: 400, Code: "invalid", Message: "A country allowlist needs a GeoIP database. Refusing to save the policy."}
	}
	old, had := s.State.Policy(keyID)
	var report *DryRunReport
	if in.Mode == model.ModeAutoDisable && (!had || old.Mode != model.ModeAutoDisable) {
		rep, err := s.DryRun(ctx, keyID)
		if err != nil {
			return state.Policy{}, nil, err
		}
		report = &rep
		if !in.Confirm {
			return state.Policy{}, report, &OpError{Status: 409, Code: "confirm_required", Message: "Switching to auto_disable needs confirmation. Review the dry-run report.", Report: report}
		}
	}
	p := model.Policy{
		KeyID: keyID, Mode: in.Mode, RPM: in.RPM, DailyCapMicro: in.DailyCapMicro, MonthlyCapMicro: in.MonthlyCapMicro,
		PathAllowlist: in.Paths, ModelAllowlist: in.Models, CIDRAllowlist: in.CIDRs, CountryAllowlist: in.Countries,
		UpdatedAt: s.now(),
	}
	parsed, err := state.ParsePolicy(p)
	if err != nil {
		return state.Policy{}, nil, &OpError{Status: 400, Code: "invalid", Message: err.Error()}
	}
	if err := s.Store.UpsertPolicy(ctx, p); err != nil {
		return state.Policy{}, nil, err
	}
	s.State.PutPolicy(parsed)
	s.audit(ctx, actor, "policy.set", keyID, old.Mode, in.Mode, ip)
	return parsed, report, nil
}

func (s *Service) DryRun(ctx context.Context, keyID string) (DryRunReport, error) {
	if _, ok := s.State.Key(keyID); !ok {
		return DryRunReport{}, &OpError{Status: 404, Code: "not_found", Message: "Virtual key not found."}
	}
	now := s.now()
	since := now.Add(-7 * 24 * time.Hour)
	events, err := s.Store.EventsSince(ctx, keyID, since)
	if err != nil {
		return DryRunReport{}, err
	}
	bases, err := s.Store.ListBaselines(ctx)
	if err != nil {
		return DryRunReport{}, err
	}
	var base model.Baseline
	for _, b := range bases {
		if b.KeyID == keyID {
			base = b
			break
		}
	}
	countries := map[string]time.Time{}
	for c, t := range base.Countries {
		if t.Before(since) {
			countries[c] = t
		}
	}
	asns := map[int]time.Time{}
	for a, t := range base.ASNs {
		if t.Before(since) {
			asns[a] = t
		}
	}
	prior := base.RequestCount - len(events)
	if prior < 0 {
		prior = 0
	}
	eng := detect.New(s.Clock, s.Rules)
	eng.LoadBaseline(model.Baseline{KeyID: keyID, FirstSeen: base.FirstSeen, RequestCount: prior, Countries: countries, ASNs: asns})
	report := DryRunReport{From: since, To: now}
	armed := false
	for _, ev := range events {
		ev.Mode = model.ModeAutoDisable
		ev.PausedUntil = time.Time{}
		out := eng.Observe(ev)
		report.Detections += len(out.Detections)
		if out.DisableKey && !armed {
			armed = true
			t := ev.Time
			report.WouldDisable = true
			report.WouldDisableAt = &t
			continue
		}
		if armed {
			report.RequestsWouldBlock++
		}
	}
	return report, nil
}

func (s *Service) Rekey(ctx context.Context, oldMaster, newMaster []byte, actor, ip string) error {
	meta, ok, err := s.Store.LoadMeta(ctx)
	if err != nil || !ok {
		return &OpError{Status: 500, Code: "store_unavailable", Message: "Master key metadata is unavailable."}
	}
	dek, err := cryptoenc.UnwrapDEK(oldMaster, meta.DEKNonce, meta.WrappedDEK)
	if err != nil {
		return &OpError{Status: 401, Code: "invalid_key", Message: "The old master key does not unwrap the data key."}
	}
	nonce, wrapped, err := cryptoenc.WrapDEK(newMaster, dek)
	for i := range dek {
		dek[i] = 0
	}
	if err != nil {
		return err
	}
	if err := s.Store.UpdateMetaKeys(ctx, wrapped, nonce, meta.KEKVersion+1); err != nil {
		return err
	}
	s.audit(ctx, actor, "rekey", "dek", "", "", ip)
	return nil
}

func (s *Service) RotateAdminToken(ctx context.Context, actor, ip string) (string, error) {
	token, err := keyfmt.GenerateAdminToken()
	if err != nil {
		return "", err
	}
	hash := keyfmt.HashToken(token)
	if err := s.Store.UpdateAdminHash(ctx, hash); err != nil {
		return "", err
	}
	s.State.SetAdminHash(hash)
	s.audit(ctx, actor, "admin_token.rotate", "admin", "", "", ip)
	return token, nil
}

func (s *Service) AddAlert(ctx context.Context, kind, url, secret, actor, ip string) (model.AlertDestination, error) {
	if kind != "slack" && kind != "webhook" {
		return model.AlertDestination{}, &OpError{Status: 400, Code: "invalid", Message: "Alert kind must be slack or webhook."}
	}
	if url == "" || !(strings.HasPrefix(url, "https://") || strings.HasPrefix(url, "http://")) {
		return model.AlertDestination{}, &OpError{Status: 400, Code: "invalid", Message: "Alert URL must be http or https."}
	}
	if kind == "webhook" && secret == "" {
		return model.AlertDestination{}, &OpError{Status: 400, Code: "invalid", Message: "A webhook alert needs a signing secret."}
	}
	id, err := keyfmt.NewID("al", 12)
	if err != nil {
		return model.AlertDestination{}, err
	}
	a := model.AlertDestination{ID: id, Kind: kind, URL: url, CreatedAt: s.now()}
	if secret != "" {
		nonce, ct, err := s.Box.Encrypt([]byte(id), []byte(secret))
		if err != nil {
			return model.AlertDestination{}, err
		}
		if err := s.Store.InsertAlertSecret(ctx, a, ct, nonce); err != nil {
			return model.AlertDestination{}, err
		}
		a.Secret = secret
	} else if err := s.Store.InsertAlert(ctx, a); err != nil {
		return model.AlertDestination{}, err
	}
	s.noteSecret(secret)
	s.audit(ctx, actor, "alert.create", id, "", kind, ip)
	a.Secret = ""
	return a, nil
}

func (s *Service) Alerts(ctx context.Context) ([]model.AlertDestination, error) {
	rows, err := s.Store.ListAlerts(ctx)
	if err != nil {
		return nil, err
	}
	var out []model.AlertDestination
	for _, row := range rows {
		a := model.AlertDestination{ID: row.ID, Kind: row.Kind, URL: row.URL, CreatedAt: row.CreatedAt}
		if len(row.Ciphertext) > 0 && s.Box != nil {
			plain, err := s.Box.Decrypt([]byte(row.ID), row.Nonce, row.Ciphertext)
			if err == nil {
				a.Secret = string(plain)
			}
		}
		out = append(out, a)
	}
	return out, nil
}

// SetClientName remembers a label for a client address. An empty name clears it.
// The label is shared by every virtual key that sees that address.
func (s *Service) SetClientName(ctx context.Context, ip, name, actor, caller string) (string, string, error) {
	ip, err := canonicalClientIP(ip)
	if err != nil {
		return "", "", err
	}
	name, err = cleanClientName(name)
	if err != nil {
		return "", "", err
	}
	names, err := s.Store.ClientNames(ctx)
	if err != nil {
		return "", "", err
	}
	before := names[ip]
	if before == name {
		return ip, name, nil
	}
	if err := s.Store.SetClientName(ctx, ip, name); err != nil {
		return "", "", err
	}
	s.audit(ctx, actor, "client.name", ip, before, name, caller)
	return ip, name, nil
}

func canonicalClientIP(ip string) (string, error) {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return "", &OpError{Status: 400, Code: "invalid", Message: "Client address is not a valid IP."}
	}
	return parsed.String(), nil
}

func cleanClientName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", nil
	}
	if len([]rune(name)) > 32 {
		return "", &OpError{Status: 400, Code: "invalid", Message: "Client name must be 32 characters or fewer."}
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return "", &OpError{Status: 400, Code: "invalid", Message: "Client name cannot contain control characters."}
		}
	}
	return name, nil
}

func checkAuth(c model.Credential) error {
	switch c.AuthStyle {
	case "", model.AuthHeader:
		c.AuthStyle = model.AuthHeader
		if headers.TemplateHeaderName(c.HeaderTemplate) == "" {
			return &OpError{Status: 400, Code: "invalid", Message: "Header template must look like \"Authorization: Bearer {key}\"."}
		}
	case model.AuthBasic:
		if c.SecretIsUserPass {
			return nil
		}
	default:
		return &OpError{Status: 400, Code: "invalid", Message: "Auth style must be header or basic."}
	}
	return nil
}

func validHost(h string) bool {
	if h == "" || len(h) > 253 || strings.ContainsAny(h, "/\\?#@ \t") {
		return false
	}
	return true
}

func last4(s string) string {
	if len(s) <= 4 {
		return "****"
	}
	return s[len(s)-4:]
}

func conflict(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return &OpError{Status: 404, Code: "not_found", Message: "Not found."}
	}
	if strings.Contains(strings.ToLower(err.Error()), "unique") {
		return &OpError{Status: 409, Code: "conflict", Message: "That name is already in use."}
	}
	return err
}

// Handler serves the admin API and /metrics. Every route needs the admin token.
type Handler struct {
	Service *Service
	Metrics http.Handler
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token := bearer(r)
	if !h.Service.State.AdminOK(token) {
		apierr.Write(w, http.StatusUnauthorized, "invalid_key", "The admin token is invalid.")
		return
	}
	actor := "admin"
	ip := r.RemoteAddr
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/metrics":
		if h.Metrics != nil {
			h.Metrics.ServeHTTP(w, r)
		}
		return
	case r.Method == http.MethodPost && r.URL.Path == "/v1/upstreams":
		var req struct {
			Name               string   `json:"name"`
			Protocol           string   `json:"protocol"`
			Profile            string   `json:"profile"`
			Host               string   `json:"host"`
			Port               int      `json:"port"`
			TLS                bool     `json:"tls"`
			InsecureSkipVerify bool     `json:"insecure_skip_verify"`
			ServerName         string   `json:"server_name"`
			PathAllowlist      []string `json:"path_allowlist"`
			InjectUsage        *bool    `json:"inject_usage"`
		}
		if !decode(w, r, &req) {
			return
		}
		inject := true
		if req.InjectUsage != nil {
			inject = *req.InjectUsage
		}
		u, err := h.Service.CreateUpstream(r.Context(), model.Upstream{
			Name: req.Name, Protocol: req.Protocol, Profile: req.Profile, Host: req.Host, Port: req.Port,
			TLS: req.TLS, InsecureSkipVerify: req.InsecureSkipVerify, ServerName: req.ServerName,
			PathAllowlist: req.PathAllowlist, InjectUsage: inject,
		}, actor, ip)
		write(w, u, err)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/upstreams":
		list := h.Service.State.Upstreams()
		sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
		write(w, list, nil)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/credentials":
		var req struct {
			UpstreamID       string `json:"upstream_id"`
			Name             string `json:"name"`
			AuthStyle        string `json:"auth_style"`
			HeaderTemplate   string `json:"header_template"`
			BasicUsername    string `json:"basic_username"`
			SecretIsUserPass bool   `json:"secret_is_userpass"`
			Secret           string `json:"secret"`
		}
		if !decode(w, r, &req) {
			return
		}
		if req.AuthStyle == "" {
			req.AuthStyle = model.AuthHeader
		}
		c, err := h.Service.CreateCredential(r.Context(), model.Credential{
			UpstreamID: req.UpstreamID, Name: req.Name, AuthStyle: req.AuthStyle, HeaderTemplate: req.HeaderTemplate,
			BasicUsername: req.BasicUsername, SecretIsUserPass: req.SecretIsUserPass,
		}, req.Secret, actor, ip)
		write(w, c, err)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/credentials":
		list := h.Service.State.Credentials()
		sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
		write(w, list, nil)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/credentials/") && strings.HasSuffix(r.URL.Path, "/rotate"):
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/credentials/"), "/rotate")
		var req struct {
			Secret string `json:"secret"`
		}
		if !decode(w, r, &req) {
			return
		}
		c, err := h.Service.RotateCredential(r.Context(), id, req.Secret, actor, ip)
		write(w, c, err)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/keys":
		var req struct {
			CredentialID string     `json:"credential_id"`
			Name         string     `json:"name"`
			Kind         string     `json:"kind"`
			ExpiresAt    *time.Time `json:"expires_at"`
			NoExpiry     bool       `json:"no_expiry"`
		}
		if !decode(w, r, &req) {
			return
		}
		token, key, err := h.Service.CreateKey(r.Context(), req.CredentialID, req.Name, req.Kind, req.ExpiresAt, req.NoExpiry, actor, ip)
		if err != nil {
			write(w, nil, err)
			return
		}
		write(w, createdView(token, key), nil)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/keys":
		write(w, h.keyViews(r.Context()), nil)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/keys/"):
		rest := strings.TrimPrefix(r.URL.Path, "/v1/keys/")
		id, action, ok := strings.Cut(rest, "/")
		if !ok {
			http.NotFound(w, r)
			return
		}
		switch action {
		case "disable", "enable", "revoke":
			status := model.StatusDisabled
			if action == "enable" {
				status = model.StatusActive
			}
			if action == "revoke" {
				status = model.StatusRevoked
			}
			k, err := h.Service.SetStatus(r.Context(), id, status, actor, ip)
			write(w, k, err)
		case "rotate":
			var req struct {
				GraceSeconds *int64 `json:"grace_seconds"`
			}
			if !decode(w, r, &req) {
				return
			}
			grace := 24 * time.Hour
			if req.GraceSeconds != nil {
				grace = time.Duration(*req.GraceSeconds) * time.Second
			}
			rot, err := h.Service.RotateKey(r.Context(), id, grace, actor, ip)
			if err != nil {
				write(w, nil, err)
				return
			}
			out := createdView(rot.Token, rot.New)
			out["replaced"] = map[string]any{"id": rot.Old.ID, "name": rot.Old.Name, "status": rot.Old.Status, "expires_at": rot.Old.ExpiresAt}
			write(w, out, nil)
		case "dry-run":
			if r.Method != http.MethodGet && r.Method != http.MethodPost {
				http.NotFound(w, r)
				return
			}
			rep, err := h.Service.DryRun(r.Context(), id)
			write(w, rep, err)
		default:
			http.NotFound(w, r)
		}
	case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/v1/keys/") && strings.HasSuffix(r.URL.Path, "/policy"):
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/keys/"), "/policy")
		var req PolicyInput
		if !decode(w, r, &req) {
			return
		}
		p, report, err := h.Service.SetPolicy(r.Context(), id, req, actor, ip)
		if err != nil {
			write(w, nil, err)
			return
		}
		write(w, map[string]any{"policy": p.Policy, "dry_run": report}, nil)
	case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/v1/keys/") && strings.HasSuffix(r.URL.Path, "/expiry"):
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/keys/"), "/expiry")
		var req struct {
			ExpiresAt *time.Time `json:"expires_at"`
		}
		if !decode(w, r, &req) {
			return
		}
		k, err := h.Service.SetExpiry(r.Context(), id, req.ExpiresAt, actor, ip)
		write(w, k, err)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/keys/") && strings.HasSuffix(r.URL.Path, "/dry-run"):
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/keys/"), "/dry-run")
		rep, err := h.Service.DryRun(r.Context(), id)
		write(w, rep, err)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/keys/") && strings.HasSuffix(r.URL.Path, "/usage"):
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/keys/"), "/usage")
		if _, ok := h.Service.State.Key(id); !ok {
			write(w, nil, &OpError{Status: 404, Code: "not_found", Message: "Virtual key not found."})
			return
		}
		usage, err := h.Service.Store.KeyUsage(r.Context(), id, store.UsageListLimit)
		write(w, usage, err)
	case r.Method == http.MethodPut && r.URL.Path == "/v1/clients":
		var req struct {
			IP   string `json:"ip"`
			Name string `json:"name"`
		}
		if !decode(w, r, &req) {
			return
		}
		savedIP, savedName, err := h.Service.SetClientName(r.Context(), req.IP, req.Name, actor, ip)
		if err != nil {
			write(w, nil, err)
			return
		}
		write(w, map[string]string{"ip": savedIP, "name": savedName}, nil)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/rekey":
		var req struct {
			OldMasterKey string `json:"old_master_key"`
			NewMasterKey string `json:"new_master_key"`
		}
		if !decode(w, r, &req) {
			return
		}
		oldKey, err := cryptoenc.ParseMasterKey([]byte(req.OldMasterKey))
		if err != nil {
			write(w, nil, &OpError{Status: 400, Code: "invalid", Message: "The old master key must be 32 bytes."})
			return
		}
		newKey, err := cryptoenc.ParseMasterKey([]byte(req.NewMasterKey))
		if err != nil {
			write(w, nil, &OpError{Status: 400, Code: "invalid", Message: "The new master key must be 32 bytes."})
			return
		}
		write(w, map[string]string{"status": "ok"}, h.Service.Rekey(r.Context(), oldKey, newKey, actor, ip))
	case r.Method == http.MethodPost && r.URL.Path == "/v1/admin-token/rotate":
		token, err := h.Service.RotateAdminToken(r.Context(), actor, ip)
		write(w, map[string]string{"token": token}, err)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/alerts":
		var req struct {
			Kind   string `json:"kind"`
			URL    string `json:"url"`
			Secret string `json:"secret"`
		}
		if !decode(w, r, &req) {
			return
		}
		a, err := h.Service.AddAlert(r.Context(), req.Kind, req.URL, req.Secret, actor, ip)
		write(w, a, err)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/alerts":
		list, err := h.Service.Alerts(r.Context())
		for i := range list {
			list[i].Secret = ""
		}
		write(w, list, err)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/detections":
		since := h.Service.now().Add(-90 * 24 * time.Hour)
		list, err := h.Service.Store.DetectionsSince(r.Context(), r.URL.Query().Get("key_id"), since)
		write(w, list, err)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/audit":
		list, err := h.Service.Store.ListAudit(r.Context(), 200)
		write(w, list, err)
	default:
		// Policy JSON field names: accept the wire format on PUT by re-reading when the typed decode used the wrong shape.
		http.NotFound(w, r)
	}
}

func createdView(token string, key model.VirtualKey) map[string]any {
	return map[string]any{
		"id": key.ID, "token": token, "kind": key.Kind, "status": key.Status, "name": key.Name,
		"credential_id": key.CredentialID, "expires_at": key.ExpiresAt,
	}
}

// keyViews is the key list with each key's last use, recent detection count,
// and exposure findings. Activity is best effort: a store error leaves it out.
func (h *Handler) keyViews(ctx context.Context) []map[string]any {
	keys := h.Service.State.Keys()
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Name != keys[j].Name {
			return keys[i].Name < keys[j].Name
		}
		return keys[i].ID < keys[j].ID
	})
	now := h.Service.now()
	var activity map[string]store.Activity
	var names map[string]string
	if h.Service.Store != nil {
		a, err := h.Service.Store.KeyActivity(ctx, now.Add(-7*24*time.Hour))
		if err == nil {
			activity = a
		}
		if n, err := h.Service.Store.ClientNames(ctx); err == nil {
			names = n
		}
	}
	var out []map[string]any
	for _, k := range keys {
		view := map[string]any{
			"id": k.ID, "credential_id": k.CredentialID, "name": k.Name, "kind": k.Kind,
			"status": k.Status, "expires_at": k.ExpiresAt, "paused_until": k.PausedUntil,
			"dry_run_armed": k.DryRunArmed, "dry_run_blocked": k.DryRunBlocked, "created_at": k.CreatedAt,
		}
		facts := exposure.Facts{
			Ref: k.ID, Kind: k.Kind, Status: k.Status, ExpiresAt: k.ExpiresAt, CreatedAt: k.CreatedAt,
			Rotated: strings.HasSuffix(k.Name, RotatedSuffix),
		}
		if a, ok := activity[k.ID]; ok {
			if !a.LastSeen.IsZero() {
				view["last_seen_at"] = a.LastSeen
				view["last_ip"] = a.LastIP
				view["last_country"] = a.Country
				if name := names[a.LastIP]; name != "" {
					view["last_client_name"] = name
				}
			}
			view["detections_7d"] = a.Detections
			facts.LastSeen = a.LastSeen
		}
		if p, ok := h.Service.State.Policy(k.ID); ok {
			view["policy"] = p.Policy
			facts.CIDRs = p.Policy.CIDRAllowlist
			facts.Countries = p.Policy.CountryAllowlist
		}
		if activity != nil {
			findings := exposure.Check(facts, now)
			if findings == nil {
				findings = []exposure.Finding{}
			}
			view["exposure"] = findings
		}
		if c, ok := h.Service.State.Credential(k.CredentialID); ok {
			view["credential_last4"] = c.Last4
		}
		day, month, open := h.Service.State.Spend(k.ID, h.Service.now())
		view["spend_today_microusd"] = day
		view["spend_month_microusd"] = month
		view["spend_open_microusd"] = open
		out = append(out, view)
	}
	return out
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) >= 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func decode(w http.ResponseWriter, r *http.Request, dest any) bool {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dest); err != nil {
		apierr.Write(w, http.StatusBadRequest, "invalid", decodeMessage(err))
		return false
	}
	return true
}

func decodeMessage(err error) string {
	if err == nil {
		return "The request body is not valid JSON."
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "unknown field"):
		return "The request body has an unknown field. " + msg
	default:
		var typ *json.UnmarshalTypeError
		if errors.As(err, &typ) {
			return "The request body has a field of the wrong type (" + typ.Field + ")."
		}
		return "The request body is not valid JSON: " + msg
	}
}

func write(w http.ResponseWriter, v any, err error) {
	if err != nil {
		var op *OpError
		if errors.As(err, &op) {
			if op.Report != nil {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-Keman-Error", op.Code)
				w.WriteHeader(op.Status)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error":   map[string]string{"type": "keman_error", "code": op.Code, "message": op.Message},
					"dry_run": op.Report,
				})
				return
			}
			apierr.Write(w, op.Status, op.Code, op.Message)
			return
		}
		apierr.Write(w, http.StatusInternalServerError, "store_unavailable", "The admin request failed.")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(v)
}
