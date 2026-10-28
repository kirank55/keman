package tui

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kirank55/keman/internal/adminclient"
)

// HTTP is the admin API behind the terminal UI.
type HTTP struct {
	c *adminclient.Client
}

// NewHTTP wraps an admin client.
func NewHTTP(c *adminclient.Client) *HTTP {
	return &HTTP{c: c}
}

func (h *HTTP) ListKeys(ctx context.Context) ([]Key, error) {
	var wire []keyWire
	if err := h.c.Call(ctx, http.MethodGet, "/v1/keys", nil, &wire); err != nil {
		return nil, explain(err, h.c.Base)
	}
	out := make([]Key, 0, len(wire))
	for _, w := range wire {
		out = append(out, w.toKey())
	}
	return out, nil
}

func (h *HTTP) ListDetections(ctx context.Context, keyID string) ([]Detection, error) {
	path := "/v1/detections"
	if keyID != "" {
		path += "?key_id=" + url.QueryEscape(keyID)
	}
	var wire []struct {
		Time     string `json:"time"`
		KeyID    string `json:"virtual_key_id"`
		Rule     string `json:"rule"`
		Severity string `json:"severity"`
	}
	if err := h.c.Call(ctx, http.MethodGet, path, nil, &wire); err != nil {
		return nil, explain(err, h.c.Base)
	}
	out := make([]Detection, 0, len(wire))
	for _, w := range wire {
		d := Detection{KeyID: w.KeyID, Rule: w.Rule, Severity: w.Severity}
		if w.Time != "" {
			if t, err := parseTime(w.Time); err == nil {
				d.Time = t
			}
		}
		out = append(out, d)
	}
	return out, nil
}

func (h *HTTP) ListAudit(ctx context.Context) ([]AuditRow, error) {
	var wire []struct {
		Time   string `json:"time"`
		Actor  string `json:"actor"`
		Action string `json:"action"`
		Target string `json:"target"`
	}
	if err := h.c.Call(ctx, http.MethodGet, "/v1/audit", nil, &wire); err != nil {
		return nil, explain(err, h.c.Base)
	}
	out := make([]AuditRow, 0, len(wire))
	for _, w := range wire {
		row := AuditRow{Actor: w.Actor, Action: w.Action, Target: w.Target}
		if w.Time != "" {
			if t, err := parseTime(w.Time); err == nil {
				row.Time = t
			}
		}
		out = append(out, row)
	}
	return out, nil
}

func (h *HTTP) ListUpstreams(ctx context.Context) ([]Upstream, error) {
	var wire []struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Profile string `json:"profile"`
		Host    string `json:"host"`
		Port    int    `json:"port"`
		TLS     bool   `json:"tls"`
	}
	if err := h.c.Call(ctx, http.MethodGet, "/v1/upstreams", nil, &wire); err != nil {
		return nil, explain(err, h.c.Base)
	}
	out := make([]Upstream, 0, len(wire))
	for _, w := range wire {
		out = append(out, Upstream{ID: w.ID, Name: w.Name, Profile: w.Profile, Host: w.Host, Port: w.Port, TLS: w.TLS})
	}
	return out, nil
}

func (h *HTTP) ListCredentials(ctx context.Context) ([]Credential, error) {
	var wire []struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		UpstreamID string `json:"upstream_id"`
		AuthStyle  string `json:"auth_style"`
		Last4      string `json:"last4"`
	}
	if err := h.c.Call(ctx, http.MethodGet, "/v1/credentials", nil, &wire); err != nil {
		return nil, explain(err, h.c.Base)
	}
	out := make([]Credential, 0, len(wire))
	for _, w := range wire {
		out = append(out, Credential{ID: w.ID, Name: w.Name, UpstreamID: w.UpstreamID, AuthStyle: w.AuthStyle, Last4: w.Last4})
	}
	return out, nil
}

func (h *HTTP) ListAlerts(ctx context.Context) ([]AlertDest, error) {
	var wire []struct {
		ID   string `json:"id"`
		Kind string `json:"kind"`
		URL  string `json:"url"`
	}
	if err := h.c.Call(ctx, http.MethodGet, "/v1/alerts", nil, &wire); err != nil {
		return nil, explain(err, h.c.Base)
	}
	out := make([]AlertDest, 0, len(wire))
	for _, w := range wire {
		out = append(out, AlertDest{ID: w.ID, Kind: w.Kind, URL: w.URL})
	}
	return out, nil
}

func (h *HTTP) SetStatus(ctx context.Context, id, action string) error {
	err := h.c.Call(ctx, http.MethodPost, "/v1/keys/"+url.PathEscape(id)+"/"+url.PathEscape(action), map[string]any{}, nil)
	if err != nil {
		return explain(err, h.c.Base)
	}
	return nil
}

func (h *HTTP) PutPolicy(ctx context.Context, id string, p Policy, confirm bool) (DryRun, error) {
	body := map[string]any{
		"mode":                 p.Mode,
		"rpm":                  p.RPM,
		"daily_cap_microusd":   p.DailyCapMicro,
		"monthly_cap_microusd": p.MonthlyCapMicro,
		"paths":                p.Paths,
		"models":               p.Models,
		"cidrs":                p.CIDRs,
		"countries":            p.Countries,
		"confirm":              confirm,
	}
	err := h.c.Call(ctx, http.MethodPut, "/v1/keys/"+url.PathEscape(id)+"/policy", body, nil)
	if err == nil {
		return DryRun{}, nil
	}
	var apiErr *adminclient.APIError
	if errors.As(err, &apiErr) && apiErr.Code == "confirm_required" {
		parsed, perr := parseConfirm(apiErr.Body)
		if perr != nil {
			return DryRun{}, explain(err, h.c.Base)
		}
		return parsed.Report, parsed
	}
	return DryRun{}, explain(err, h.c.Base)
}

func (h *HTTP) KeyUsage(ctx context.Context, id string) (KeyUsage, error) {
	var wire usageWire
	if err := h.c.Call(ctx, http.MethodGet, "/v1/keys/"+url.PathEscape(id)+"/usage", nil, &wire); err != nil {
		return KeyUsage{}, explain(err, h.c.Base)
	}
	return wire.toUsage(), nil
}

func (h *HTTP) AddUpstream(ctx context.Context, d UpstreamDraft) (Upstream, error) {
	body := map[string]any{
		"name": d.Name, "profile": d.Profile, "host": d.Host,
		"protocol": "http", "port": d.Port, "tls": d.TLS,
		"path_allowlist": d.Paths,
	}
	var out struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Profile string `json:"profile"`
		Host    string `json:"host"`
		Port    int    `json:"port"`
		TLS     bool   `json:"tls"`
	}
	if err := h.c.Call(ctx, http.MethodPost, "/v1/upstreams", body, &out); err != nil {
		return Upstream{}, explain(err, h.c.Base)
	}
	return Upstream{ID: out.ID, Name: out.Name, Profile: out.Profile, Host: out.Host, Port: out.Port, TLS: out.TLS}, nil
}

func (h *HTTP) AddCredential(ctx context.Context, d CredentialDraft) (Credential, error) {
	body := map[string]any{
		"upstream_id": d.UpstreamID, "name": d.Name, "secret": d.Secret,
		"auth_style": "header", "header_template": "Authorization: Bearer {key}",
	}
	var out struct {
		ID         string `json:"id"`
		UpstreamID string `json:"upstream_id"`
		Name       string `json:"name"`
		AuthStyle  string `json:"auth_style"`
		Last4      string `json:"last4"`
	}
	if err := h.c.Call(ctx, http.MethodPost, "/v1/credentials", body, &out); err != nil {
		return Credential{}, explain(err, h.c.Base)
	}
	return Credential{ID: out.ID, UpstreamID: out.UpstreamID, Name: out.Name, AuthStyle: out.AuthStyle, Last4: out.Last4}, nil
}

func (h *HTTP) CreateKey(ctx context.Context, credentialID, name, kind string) (CreatedKey, error) {
	var out struct {
		ID     string `json:"id"`
		Token  string `json:"token"`
		Kind   string `json:"kind"`
		Status string `json:"status"`
		Name   string `json:"name"`
	}
	body := map[string]string{"credential_id": credentialID, "name": name, "kind": kind}
	if err := h.c.Call(ctx, http.MethodPost, "/v1/keys", body, &out); err != nil {
		return CreatedKey{}, explain(err, h.c.Base)
	}
	return CreatedKey{ID: out.ID, Name: out.Name, Token: out.Token, Kind: out.Kind, Status: out.Status}, nil
}

func (h *HTTP) SetExpiry(ctx context.Context, id string, at *time.Time) error {
	body := map[string]any{"expires_at": at}
	if err := h.c.Call(ctx, http.MethodPut, "/v1/keys/"+url.PathEscape(id)+"/expiry", body, nil); err != nil {
		return explain(err, h.c.Base)
	}
	return nil
}

func (h *HTTP) RotateKey(ctx context.Context, id string, grace time.Duration) (Rotation, error) {
	var out struct {
		ID       string `json:"id"`
		Token    string `json:"token"`
		Kind     string `json:"kind"`
		Status   string `json:"status"`
		Name     string `json:"name"`
		Replaced struct {
			Name      string     `json:"name"`
			Status    string     `json:"status"`
			ExpiresAt *time.Time `json:"expires_at"`
		} `json:"replaced"`
	}
	body := map[string]any{"grace_seconds": int64(grace / time.Second)}
	if err := h.c.Call(ctx, http.MethodPost, "/v1/keys/"+url.PathEscape(id)+"/rotate", body, &out); err != nil {
		return Rotation{}, explain(err, h.c.Base)
	}
	return Rotation{
		Key:     CreatedKey{ID: out.ID, Name: out.Name, Token: out.Token, Kind: out.Kind, Status: out.Status},
		OldName: out.Replaced.Name, OldUntil: out.Replaced.ExpiresAt, OldRevoked: out.Replaced.Status == "revoked",
	}, nil
}

// adminGate is implemented by the real admin client. A missing token asks
// for one inside the terminal instead of refusing to start.
type adminGate interface {
	HasAdminToken() bool
	SetAdminToken(token string)
}

func (h *HTTP) HasAdminToken() bool {
	return h != nil && h.c != nil && strings.TrimSpace(h.c.Token) != ""
}

func (h *HTTP) SetAdminToken(token string) {
	if h != nil && h.c != nil {
		h.c.Token = strings.TrimSpace(token)
	}
}

type callError struct {
	status int
	msg    string
}

func (e *callError) Error() string {
	if e == nil {
		return ""
	}
	return e.msg
}

func unauthorized(err error) bool {
	var call *callError
	return errors.As(err, &call) && call.status == http.StatusUnauthorized
}

func explain(err error, base string) error {
	if err == nil {
		return nil
	}
	var apiErr *adminclient.APIError
	if errors.As(err, &apiErr) {
		msg := apiErr.Message
		if msg == "" {
			msg = apiErr.Error()
		}
		return &callError{status: apiErr.Status, msg: msg}
	}
	var u *url.Error
	if errors.As(err, &u) {
		return fmt.Errorf("admin API is not reachable at %s", base)
	}
	return err
}
