// Package proxy is the HTTP reverse proxy. Callers send a virtual key.
// Keman checks it, swaps in the credential, and streams the upstream response.
package proxy

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kirank55/keman/internal/apierr"
	"github.com/kirank55/keman/internal/clientip"
	"github.com/kirank55/keman/internal/clock"
	"github.com/kirank55/keman/internal/headers"
	"github.com/kirank55/keman/internal/keyfmt"
	"github.com/kirank55/keman/internal/model"
	"github.com/kirank55/keman/internal/pathmatch"
	"github.com/kirank55/keman/internal/pipeline"
	"github.com/kirank55/keman/internal/price"
	"github.com/kirank55/keman/internal/profile"
	"github.com/kirank55/keman/internal/state"
	"github.com/kirank55/keman/internal/usage"
)

type Geo interface {
	Lookup(ip net.IP) (country string, asn int)
}

type Metrics interface {
	Request(code, profile string)
	Observe(profile string, seconds float64)
	Dropped(n int)
}

// Proxy is safe for concurrent use.
type Proxy struct {
	State              *state.State
	Clock              clock.Clock
	Prices             *price.Table
	Queue              *pipeline.Queue
	Geo                Geo
	Trusted            []*net.IPNet
	DefaultReservation int64
	MaxBody            int64
	DialTimeout        time.Duration
	HeaderTimeout      time.Duration
	FailClosedAfter    time.Duration
	Log                *slog.Logger
	Secrets            interface{ Add(string) }
	Metrics            Metrics
	Transport          http.RoundTripper

	mu    sync.Mutex
	trans map[string]*http.Transport
}

func (p *Proxy) now() time.Time {
	if p.Clock != nil {
		return p.Clock.Now()
	}
	return time.Now().UTC()
}

func (p *Proxy) log() *slog.Logger {
	if p.Log != nil {
		return p.Log
	}
	return slog.Default()
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := p.now()
	ip := clientip.FromRequest(r.RemoteAddr, r.Header.Get("X-Forwarded-For"), p.Trusted)
	ipStr := ""
	if ip != nil {
		ipStr = ip.String()
	}
	token := presentedKey(r)
	id, secret, err := keyfmt.Parse(token)
	if err != nil {
		p.rejectUnauth(w, r, ipStr, start, "invalid_key")
		return
	}
	key, ok := p.State.Match(id, secret)
	if !ok {
		p.rejectUnauth(w, r, ipStr, start, "invalid_key")
		return
	}
	if p.Secrets != nil {
		p.Secrets.Add(secret)
	}
	cred, ok := p.State.Credential(key.CredentialID)
	if !ok {
		p.failEvent(w, model.Event{Time: start, KeyID: key.ID, Kind: key.Kind, IP: ipStr}, "store_unavailable", start)
		return
	}
	if p.Secrets != nil {
		p.Secrets.Add(cred.Plaintext)
	}
	up, ok := p.State.Upstream(cred.UpstreamID)
	if !ok {
		p.failEvent(w, model.Event{Time: start, KeyID: key.ID, Kind: key.Kind, IP: ipStr}, "store_unavailable", start)
		return
	}
	country, asn := "", 0
	if p.Geo != nil && ip != nil {
		country, asn = p.Geo.Lookup(ip)
	}
	pol, hasPol := p.State.Policy(key.ID)
	mode := model.ModeAlertOnly
	var paused time.Time
	if key.PausedUntil != nil {
		paused = *key.PausedUntil
	}
	if hasPol {
		mode = pol.Mode
	}

	evBase := model.Event{
		Time: start, KeyID: key.ID, Kind: key.Kind, IP: ipStr, Country: country, ASN: asn,
		Profile: up.Profile, Mode: mode, PausedUntil: paused, Model: "",
	}

	if key.Kind == model.KindCanary {
		p.writeCanary(w, up.Profile)
		evBase.Status = http.StatusUnauthorized
		evBase.BlockedCode = "canary_used"
		p.finish(r, evBase, start, 0, 0)
		return
	}
	if key.Status == model.StatusDisabled {
		p.failEvent(w, evBase, "key_disabled", start)
		return
	}
	if key.Status == model.StatusRevoked {
		p.failEvent(w, evBase, "key_revoked", start)
		return
	}
	if key.ExpiresAt != nil && !start.Before(*key.ExpiresAt) {
		p.failEvent(w, evBase, "key_expired", start)
		return
	}
	if hasPol && !state.NetworkAllowed(pol, ip, country) {
		p.failEvent(w, evBase, "network_not_allowed", start)
		return
	}

	var body []byte
	var meta usage.Meta
	if profile.IsLLM(up.Profile) && r.Body != nil && r.ContentLength != 0 {
		var err error
		body, err = readLimited(r.Body, p.maxBody())
		r.Body.Close()
		if err != nil {
			p.failEvent(w, evBase, "request_too_large", start)
			return
		}
		inject := up.InjectUsage
		body, meta = usage.Prepare(up.Profile, inject, body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		r.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(body)), nil
		}
		evBase.Model = meta.Model
		evBase.ReqBytes = int64(len(body))
	} else if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, p.maxBody())
	}

	baseRules := upRules(up)
	op, ok := pathmatch.Match(baseRules, r.Method, r.URL.Path)
	if !ok || len(baseRules) == 0 {
		p.failEvent(w, evBase, "path_not_allowed", start)
		return
	}
	if hasPol && len(pol.Paths) > 0 {
		op2, ok := pathmatch.Match(pol.Paths, r.Method, r.URL.Path)
		if !ok {
			p.failEvent(w, evBase, "path_not_allowed", start)
			return
		}
		op = op2
	}
	evBase.Operation = op

	if hasPol && len(pol.Models) > 0 && meta.HasModel {
		if _, ok := pol.Models[meta.Model]; !ok {
			p.failEvent(w, evBase, "model_not_allowed", start)
			return
		}
	}

	rpm := 0
	if hasPol && pol.RPM != nil {
		rpm = *pol.RPM
	}
	if ok, retry := p.State.AllowKey(key.ID, rpm, start); !ok {
		sec := int(retry.Seconds())
		if sec < 1 {
			sec = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(sec))
		p.failEvent(w, evBase, "rate_limited", start)
		return
	}

	hasCap := hasPol && (pol.DailyCapMicro != nil || pol.MonthlyCapMicro != nil)
	if hasCap && p.State.SpendDegraded(key.ID, start) {
		p.failEvent(w, evBase, "store_unavailable", start)
		return
	}

	var reservation int64
	if profile.IsLLM(up.Profile) && meta.HasModel && p.Prices != nil {
		if _, known := p.Prices.Lookup(meta.Model); !known {
			if hasCap {
				p.failEvent(w, evBase, "unknown_model_price", start)
				return
			}
		} else if hasCap {
			reservation, _ = p.Prices.Reserve(meta.Model, int64(len(body)), meta.MaxTokens, p.DefaultReservation)
			if !p.State.Reserve(key.ID, reservation, start) {
				p.failEvent(w, evBase, "spend_cap_reached", start)
				return
			}
		}
	}

	settled := false
	release := func() {
		if settled || reservation == 0 {
			return
		}
		settled = true
		p.State.Release(key.ID, reservation)
	}
	defer release()

	target := upstreamURL(up)
	var respBytes int64
	var result usage.Result
	proxy := &httputil.ReverseProxy{
		Director: func(out *http.Request) {
			out.URL.Scheme = target.Scheme
			out.URL.Host = target.Host
			out.URL.Path = r.URL.Path
			out.URL.RawPath = r.URL.RawPath
			out.URL.RawQuery = r.URL.RawQuery
			out.Host = target.Host
			out.Header = headers.Sanitize(out.Header)
			// A nil slice tells ReverseProxy not to append the peer address.
			out.Header["X-Forwarded-For"] = nil
			applyAuth(out, cred)
			if body != nil {
				out.Body = io.NopCloser(bytes.NewReader(body))
				out.ContentLength = int64(len(body))
				out.GetBody = func() (io.ReadCloser, error) {
					return io.NopCloser(bytes.NewReader(body)), nil
				}
			}
		},
		Transport:     p.transport(up),
		FlushInterval: -1,
		ModifyResponse: func(resp *http.Response) error {
			evBase.Status = resp.StatusCode
			if blockedRedirect(resp, up) {
				replaceError(resp, "upstream_redirect_blocked")
				evBase.Status = apierr.Status("upstream_redirect_blocked")
				evBase.BlockedCode = "upstream_redirect_blocked"
				return nil
			}
			sc := usage.NewScanner(up.Profile, resp.Header.Get("Content-Type"))
			resp.Body = &countBody{ReadCloser: resp.Body, n: &respBytes, scan: sc, onClose: func() {
				if !profile.IsLLM(up.Profile) {
					return
				}
				result = sc.Finish()
				if !hasCap {
					return
				}
				if evBase.BlockedCode != "" || isRedirect(evBase.Status) {
					return
				}
				if !result.Saw {
					p.State.Reconcile(key.ID, reservation, reservation, start)
					settled = true
					return
				}
				var cost int64
				ok := false
				if p.Prices != nil {
					cost, ok = p.Prices.Cost(meta.Model, result.Input, result.Output, result.Cached, result.CacheWrite, result.InputIncludesCached)
				}
				if !ok {
					p.State.Reconcile(key.ID, reservation, reservation, start)
					settled = true
					return
				}
				p.State.Reconcile(key.ID, reservation, cost, start)
				settled = true
			}}
			return nil
		},
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, err error) {
			p.log().Info("upstream request failed", "key_id", key.ID, "err", err.Error())
			apierr.Fail(rw, "upstream_unavailable")
			evBase.Status = apierr.Status("upstream_unavailable")
			evBase.BlockedCode = "upstream_unavailable"
		},
	}
	proxy.ServeHTTP(w, r)

	if evBase.Status == 0 {
		if evBase.BlockedCode == "upstream_unavailable" {
			evBase.Status = apierr.Status("upstream_unavailable")
		} else {
			evBase.Status = http.StatusOK
		}
	}
	if result.Saw {
		evBase.TokensIn = result.Input
		evBase.TokensOut = result.Output
		evBase.CachedTokens = result.Cached
		evBase.CacheWriteTokens = result.CacheWrite
		evBase.CostEstimated = false
		if p.Prices != nil {
			if cost, ok := p.Prices.Cost(meta.Model, result.Input, result.Output, result.Cached, result.CacheWrite, result.InputIncludesCached); ok {
				evBase.CostMicro = &cost
			}
		}
	} else if hasCap && reservation > 0 && evBase.BlockedCode == "" && !isRedirect(evBase.Status) {
		if !settled {
			p.State.Reconcile(key.ID, reservation, reservation, start)
			settled = true
		}
		c := reservation
		evBase.CostMicro = &c
		evBase.CostEstimated = true
	}
	p.finish(r, evBase, start, evBase.ReqBytes, respBytes)
}

func (p *Proxy) rejectUnauth(w http.ResponseWriter, r *http.Request, ip string, start time.Time, code string) {
	if ok, retry := p.State.AllowInvalid(ip, start); !ok {
		sec := int(retry.Seconds())
		if sec < 1 {
			sec = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(sec))
		code = "rate_limited"
	}
	apierr.Fail(w, code)
	p.log().Info("rejected", "code", code, "client_ip", ip, "latency_ms", p.now().Sub(start).Milliseconds())
	if p.Metrics != nil {
		p.Metrics.Request(code, "")
	}
}

func (p *Proxy) failEvent(w http.ResponseWriter, ev model.Event, code string, start time.Time) {
	if code == "rate_limited" {
		// Retry-After is set by the caller when it knows the delay.
	}
	apierr.Fail(w, code)
	ev.Status = apierr.Status(code)
	ev.BlockedCode = code
	p.finish(nil, ev, start, ev.ReqBytes, 0)
}

func (p *Proxy) finish(r *http.Request, ev model.Event, start time.Time, reqBytes, respBytes int64) {
	ev.LatencyMS = p.now().Sub(start).Milliseconds()
	if ev.ReqBytes == 0 {
		ev.ReqBytes = reqBytes
	}
	ev.RespBytes = respBytes
	if ev.Status == 0 {
		ev.Status = 200
	}
	p.log().Info("request",
		"key_id", ev.KeyID,
		"code", ev.BlockedCode,
		"status", ev.Status,
		"operation", ev.Operation,
		"client_ip", ev.IP,
		"latency_ms", ev.LatencyMS,
		"profile", ev.Profile,
	)
	if p.Metrics != nil {
		code := ev.BlockedCode
		if code == "" {
			code = "ok"
		}
		p.Metrics.Request(code, ev.Profile)
		p.Metrics.Observe(ev.Profile, float64(ev.LatencyMS)/1000)
	}
	if p.Queue != nil {
		if n := p.Queue.Push(ev); n > 0 && p.Metrics != nil {
			p.Metrics.Dropped(n)
		}
	}
}

func (p *Proxy) maxBody() int64 {
	if p.MaxBody <= 0 {
		return 32 << 20
	}
	return p.MaxBody
}

func (p *Proxy) writeCanary(w http.ResponseWriter, prof string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusUnauthorized)
	switch prof {
	case profile.Anthropic:
		_, _ = w.Write([]byte(`{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}` + "\n"))
	case profile.Generic:
		_, _ = w.Write([]byte(`{"error":"unauthorized"}` + "\n"))
	default:
		_, _ = w.Write([]byte(`{"error":{"message":"Incorrect API key provided.","type":"invalid_request_error","param":null,"code":"invalid_api_key"}}` + "\n"))
	}
}

func (p *Proxy) transport(up model.Upstream) http.RoundTripper {
	if p.Transport != nil {
		return p.Transport
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.trans == nil {
		p.trans = map[string]*http.Transport{}
	}
	if tr, ok := p.trans[up.ID]; ok {
		return tr
	}
	dial := p.DialTimeout
	if dial <= 0 {
		dial = 10 * time.Second
	}
	header := p.HeaderTimeout
	if header <= 0 {
		header = 60 * time.Second
	}
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: dial, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: header,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			ServerName:         up.ServerName,
			InsecureSkipVerify: up.InsecureSkipVerify,
		},
	}
	p.trans[up.ID] = tr
	return tr
}

func presentedKey(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) >= 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	if v := r.Header.Get("X-Api-Key"); v != "" {
		return strings.TrimSpace(v)
	}
	return strings.TrimSpace(h)
}

func readLimited(body io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, io.ErrUnexpectedEOF
	}
	return b, nil
}

func upRules(up model.Upstream) []pathmatch.Rule {
	if len(up.PathAllowlist) > 0 {
		rules, err := pathmatch.ParseList(strings.Join(up.PathAllowlist, "\n"))
		if err != nil {
			// Fail closed: a corrupt list must not restore the built-in allowlist.
			return nil
		}
		return rules
	}
	return profile.Builtin(up.Profile)
}

func isRedirect(status int) bool {
	return status >= 300 && status < 400
}

func upstreamURL(up model.Upstream) *url.URL {
	scheme := "http"
	if up.TLS {
		scheme = "https"
	}
	host := up.Host
	if !((scheme == "https" && up.Port == 443) || (scheme == "http" && up.Port == 80) || up.Port == 0) {
		host = net.JoinHostPort(up.Host, strconv.Itoa(up.Port))
	}
	return &url.URL{Scheme: scheme, Host: host}
}

func applyAuth(out *http.Request, cred model.Credential) {
	switch cred.AuthStyle {
	case model.AuthBasic:
		user, pass := cred.BasicUsername, cred.Plaintext
		if cred.SecretIsUserPass {
			user, pass, _ = strings.Cut(cred.Plaintext, ":")
		}
		out.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user+":"+pass)))
	default:
		if err := headers.ApplyTemplate(out.Header, cred.HeaderTemplate, cred.Plaintext); err != nil {
			out.Header.Del("Authorization")
			out.Header.Del("X-Api-Key")
		}
	}
}

func blockedRedirect(resp *http.Response, up model.Upstream) bool {
	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return false
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		return false
	}
	u, err := url.Parse(loc)
	if err != nil {
		return true
	}
	if u.Host == "" {
		return false
	}
	if !strings.EqualFold(u.Hostname(), up.Host) {
		return true
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "http" {
			port = "80"
		} else {
			port = "443"
		}
	}
	want := strconv.Itoa(up.Port)
	if up.Port == 0 {
		if up.TLS {
			want = "443"
		} else {
			want = "80"
		}
	}
	return port != want
}

func replaceError(resp *http.Response, code string) {
	resp.Body.Close()
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(map[string]any{
		"error": map[string]string{"type": "keman_error", "code": code, "message": apierr.Message(code)},
	})
	resp.StatusCode = apierr.Status(code)
	resp.Status = strconv.Itoa(resp.StatusCode) + " " + http.StatusText(resp.StatusCode)
	resp.Body = io.NopCloser(bytes.NewReader(buf.Bytes()))
	resp.ContentLength = int64(buf.Len())
	resp.Header = make(http.Header)
	resp.Header.Set("Content-Type", "application/json")
	resp.Header.Set("X-Keman-Error", code)
}

type countBody struct {
	io.ReadCloser
	n       *int64
	scan    *usage.Scanner
	onClose func()
	once    sync.Once
}

func (b *countBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		*b.n += int64(n)
		if b.scan != nil {
			b.scan.Feed(p[:n])
		}
	}
	// ReverseProxy can flush a Content-Length body to the client before Close.
	// Settle spend on EOF so usage is recorded as soon as the body is complete.
	if errors.Is(err, io.EOF) {
		b.finish()
	}
	return n, err
}

func (b *countBody) Close() error {
	b.finish()
	return b.ReadCloser.Close()
}

func (b *countBody) finish() {
	b.once.Do(func() {
		if b.onClose != nil {
			b.onClose()
		}
	})
}
