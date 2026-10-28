// Package app wires the proxy, the admin API, and the detection worker.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	stdlog "log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/kirank55/keman/internal/admin"
	"github.com/kirank55/keman/internal/alert"
	"github.com/kirank55/keman/internal/clientip"
	"github.com/kirank55/keman/internal/clock"
	"github.com/kirank55/keman/internal/config"
	"github.com/kirank55/keman/internal/cryptoenc"
	"github.com/kirank55/keman/internal/detect"
	"github.com/kirank55/keman/internal/geoip"
	"github.com/kirank55/keman/internal/headers"
	"github.com/kirank55/keman/internal/keyfmt"
	"github.com/kirank55/keman/internal/metrics"
	"github.com/kirank55/keman/internal/model"
	"github.com/kirank55/keman/internal/pathmatch"
	"github.com/kirank55/keman/internal/pipeline"
	"github.com/kirank55/keman/internal/price"
	"github.com/kirank55/keman/internal/proxy"
	"github.com/kirank55/keman/internal/redact"
	"github.com/kirank55/keman/internal/state"
	"github.com/kirank55/keman/internal/store"
)

// Init creates an empty database, a data key, and an admin token.
// The token is returned once.
func Init(ctx context.Context, cfg config.Config, master []byte) (string, error) {
	if len(master) != cryptoenc.KeySize {
		return "", fmt.Errorf("master key must be 32 bytes")
	}
	if dir := filepath.Dir(cfg.Database); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", err
		}
	}
	st, err := store.Open(cfg.Database)
	if err != nil {
		return "", err
	}
	defer st.Close()
	if _, ok, err := st.LoadMeta(ctx); err != nil {
		return "", err
	} else if ok {
		return "", fmt.Errorf("database is already initialized")
	}
	dek, err := cryptoenc.GenerateDEK()
	if err != nil {
		return "", err
	}
	nonce, wrapped, err := cryptoenc.WrapDEK(master, dek)
	for i := range dek {
		dek[i] = 0
	}
	if err != nil {
		return "", err
	}
	token, err := keyfmt.GenerateAdminToken()
	if err != nil {
		return "", err
	}
	err = st.Init(ctx, store.Meta{
		WrappedDEK: wrapped, DEKNonce: nonce, KEKVersion: 1, AdminHash: keyfmt.HashToken(token),
	}, time.Now().UTC())
	if err != nil {
		return "", err
	}
	return token, nil
}

// Initialized reports whether the database file already contains an install.
// A missing file is not initialized and is not created.
func Initialized(ctx context.Context, database string) (bool, error) {
	if _, err := os.Stat(database); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	st, err := store.Open(database)
	if err != nil {
		return false, err
	}
	defer st.Close()
	_, ok, err := st.LoadMeta(ctx)
	return ok, err
}

// CheckMaster reports whether master unwraps the data key of an existing install.
func CheckMaster(ctx context.Context, cfg config.Config, master []byte) error {
	st, err := store.Open(cfg.Database)
	if err != nil {
		return err
	}
	defer st.Close()
	meta, ok, err := st.LoadMeta(ctx)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("database is not initialized; run keman init")
	}
	if _, err := cryptoenc.UnwrapDEK(master, meta.DEKNonce, meta.WrappedDEK); err != nil {
		return fmt.Errorf("master key could not unwrap the data key")
	}
	return nil
}

type Option func(*build)

type build struct {
	clock     clock.Clock
	geo       geoip.Resolver
	log       *slog.Logger
	logWriter io.Writer
}

func WithClock(c clock.Clock) Option { return func(b *build) { b.clock = c } }
func WithGeoIP(g geoip.Resolver) Option {
	return func(b *build) { b.geo = g }
}
func WithLogger(l *slog.Logger) Option { return func(b *build) { b.log = l } }

// WithLogWriter sends server logs to w. The writer is wrapped with the process
// redactor, so credentials added later are scrubbed.
func WithLogWriter(w io.Writer) Option { return func(b *build) { b.logWriter = w } }

// App is one running Keman process.
type App struct {
	cfg       config.Config
	store     *store.Store
	state     *state.State
	engine    *detect.Engine
	box       *cryptoenc.Box
	clock     clock.Clock
	queue     *pipeline.Queue
	metrics   *metrics.Metrics
	secrets   *redact.Secrets
	log       *slog.Logger
	svc       *admin.Service
	proxyLn   net.Listener
	adminLn   net.Listener
	proxySrv  *http.Server
	adminSrv  *http.Server
	saveSpend func(context.Context, []model.SpendRow) error
	closeGeo  func() error
	cancel    context.CancelFunc
	ctx       context.Context
	stop      chan struct{}
	stopOnce  sync.Once
	wg        sync.WaitGroup
	rules     detect.Config
}

// Open loads the database and builds the process. Call Start to listen.
func Open(ctx context.Context, cfg config.Config, master []byte, opts ...Option) (*App, error) {
	var b build
	for _, opt := range opts {
		opt(&b)
	}
	if b.clock == nil {
		b.clock = clock.System{}
	}
	secrets := &redact.Secrets{}
	log := b.log
	if log == nil {
		logOut := io.Writer(os.Stderr)
		if b.logWriter != nil {
			logOut = b.logWriter
		}
		log = slog.New(redact.New(slog.NewTextHandler(logOut, &slog.HandlerOptions{Level: slog.LevelInfo}), secrets))
	}
	errLog := stdlog.New(logWriter{log}, "", 0)
	if _, err := os.Stat(cfg.Database); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("database is not initialized; run keman init")
		}
		return nil, err
	}
	st, err := store.Open(cfg.Database)
	if err != nil {
		return nil, err
	}
	meta, ok, err := st.LoadMeta(ctx)
	if err != nil {
		st.Close()
		return nil, err
	}
	if !ok {
		st.Close()
		return nil, fmt.Errorf("database is not initialized; run keman init")
	}
	dek, err := cryptoenc.UnwrapDEK(master, meta.DEKNonce, meta.WrappedDEK)
	if err != nil {
		st.Close()
		return nil, fmt.Errorf("master key could not unwrap the data key")
	}
	box, err := cryptoenc.NewBox(dek)
	if err != nil {
		st.Close()
		return nil, err
	}
	prices, err := price.Load(cfg.PricesFile)
	if err != nil {
		st.Close()
		return nil, err
	}
	trusted, err := clientip.ParseCIDRs(cfg.TrustedProxies)
	if err != nil {
		st.Close()
		return nil, fmt.Errorf("trusted proxies: %w", err)
	}
	var geo geoip.Resolver = b.geo
	var closeGeo func() error
	if geo == nil && (cfg.GeoIPCountryDB != "" || cfg.GeoIPASNDB != "") {
		db, err := geoip.Open(cfg.GeoIPCountryDB, cfg.GeoIPASNDB)
		if err != nil {
			st.Close()
			return nil, err
		}
		geo = db
		closeGeo = db.Close
	}
	rules := detect.DefaultConfig()
	mem := state.New(b.clock, cfg.InvalidKeyRPM, cfg.SpendFailClosedAfter)
	mem.SetAdminHash(meta.AdminHash)
	eng := detect.New(b.clock, rules)
	a := &App{
		cfg: cfg, store: st, state: mem, engine: eng, box: box, clock: b.clock,
		queue: pipeline.New(cfg.EventQueueSize), metrics: metrics.New(), secrets: secrets,
		log: log, closeGeo: closeGeo, rules: rules, stop: make(chan struct{}),
	}
	a.saveSpend = st.SaveSpend
	if err := a.load(ctx, geo); err != nil {
		st.Close()
		if closeGeo != nil {
			_ = closeGeo()
		}
		return nil, err
	}
	a.svc = &admin.Service{
		Store: st, State: mem, Box: box, Clock: b.clock, Rules: rules,
		GeoCountry: geo != nil && geo.HasCountry(),
		DefaultTTL: cfg.DefaultKeyTTL,
		OnStatus: func(id, status string, paused time.Time) {
			eng.NoteStatus(id, status, paused)
		},
		OnSecret: secrets.Add,
		Log:      log,
	}
	px := &proxy.Proxy{
		State: mem, Clock: b.clock, Prices: prices, Queue: a.queue, Geo: geo, Trusted: trusted,
		DefaultReservation: cfg.DefaultReservation, MaxBody: cfg.MaxRequestBodyBytes,
		DialTimeout: cfg.UpstreamDialTimeout, HeaderTimeout: cfg.UpstreamHeaderTimeout,
		Log: log, Secrets: secrets, Metrics: promAdapter{a.metrics},
	}
	a.proxySrv = &http.Server{
		Handler:           h2c.NewHandler(px, &http2.Server{}),
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    cfg.MaxHeaderBytes,
		ErrorLog:          errLog,
	}
	a.adminSrv = &http.Server{
		Handler:           &admin.Handler{Service: a.svc, Metrics: promhttp.HandlerFor(a.metrics.Registry, promhttp.HandlerOpts{})},
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    cfg.MaxHeaderBytes,
		ErrorLog:          errLog,
	}
	return a, nil
}

type logWriter struct{ log *slog.Logger }

func (w logWriter) Write(p []byte) (int, error) {
	msg := strings.TrimSpace(string(p))
	if msg != "" && w.log != nil {
		w.log.Error(msg)
	}
	return len(p), nil
}

func (a *App) load(ctx context.Context, geo geoip.Resolver) error {
	ups, err := a.store.ListUpstreams(ctx)
	if err != nil {
		return err
	}
	for _, u := range ups {
		if len(u.PathAllowlist) > 0 {
			if _, err := pathmatch.ParseList(strings.Join(u.PathAllowlist, "\n")); err != nil {
				return fmt.Errorf("upstream %s has an invalid path allowlist: %w", u.Name, err)
			}
		}
		a.state.PutUpstream(u)
	}
	creds, err := a.store.ListCredentials(ctx)
	if err != nil {
		return err
	}
	for _, c := range creds {
		plain, err := a.box.Decrypt([]byte(c.ID), c.Nonce, c.Ciphertext)
		if err != nil {
			return fmt.Errorf("decrypt credential %s: %w", c.ID, err)
		}
		c.Plaintext = string(plain)
		if c.AuthStyle == model.AuthHeader || c.AuthStyle == "" {
			if headers.TemplateHeaderName(c.HeaderTemplate) == "" {
				return fmt.Errorf("credential %s has an invalid header template", c.Name)
			}
		}
		a.secrets.Add(c.Plaintext)
		a.state.PutCredential(c)
	}
	keys, err := a.store.ListKeys(ctx)
	if err != nil {
		return err
	}
	for _, k := range keys {
		a.state.PutKey(k)
		var paused time.Time
		if k.PausedUntil != nil {
			paused = *k.PausedUntil
		}
		a.engine.NoteStatus(k.ID, k.Status, paused)
	}
	pols, err := a.store.ListPolicies(ctx)
	if err != nil {
		return err
	}
	hasCountry := geo != nil && geo.HasCountry()
	for _, p := range pols {
		if len(p.CountryAllowlist) > 0 && !hasCountry {
			return fmt.Errorf("policy on %s uses a country allowlist but no GeoIP country database is configured", p.KeyID)
		}
		parsed, err := state.ParsePolicy(p)
		if err != nil {
			return err
		}
		a.state.PutPolicy(parsed)
	}
	spend, err := a.store.LoadSpend(ctx)
	if err != nil {
		return err
	}
	a.state.LoadSpend(spend)
	bases, err := a.store.ListBaselines(ctx)
	if err != nil {
		return err
	}
	for _, b := range bases {
		if k, ok := a.state.Key(b.KeyID); ok {
			b.DryRunArmed = k.DryRunArmed
			b.DryRunBlocked = k.DryRunBlocked
		}
		a.engine.LoadBaseline(b)
	}
	now := a.clock.Now()
	events, err := a.store.EventsSince(ctx, "", now.Add(-a.rules.BaselineWindow))
	if err != nil {
		return err
	}
	for _, ev := range events {
		a.engine.Restore(ev)
	}
	dets, err := a.store.DetectionsSince(ctx, "", now.Add(-a.rules.AutoWindow))
	if err != nil {
		return err
	}
	for _, d := range dets {
		a.engine.LoadDetection(d)
	}
	incs, err := a.store.OpenIncidents(ctx, now.Add(-a.rules.IncidentQuiet))
	if err != nil {
		return err
	}
	for _, inc := range incs {
		a.engine.LoadIncident(inc.KeyID, inc.Rule, inc.OpenedAt, inc.LastFired)
	}
	return nil
}

// Start listens on the proxy and admin addresses.
func (a *App) Start() error {
	var err error
	a.proxyLn, err = listen(a.cfg.ProxyListen)
	if err != nil {
		return err
	}
	a.adminLn, err = listen(a.cfg.AdminListen)
	if err != nil {
		a.proxyLn.Close()
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	a.ctx = ctx
	a.wg.Add(4)
	go a.serve(a.proxySrv, a.proxyLn)
	go a.serve(a.adminSrv, a.adminLn)
	go a.worker()
	go a.loops()
	return nil
}

func (a *App) serve(srv *http.Server, ln net.Listener) {
	defer a.wg.Done()
	err := srv.Serve(ln)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		a.log.Error("server stopped", "err", err.Error())
	}
}

func (a *App) loops() {
	defer a.wg.Done()
	flushEvery := a.cfg.SpendFlushInterval
	if flushEvery <= 0 {
		flushEvery = 5 * time.Second
	}
	retainEvery := time.Hour
	nextFlush := a.clock.Now().Add(flushEvery)
	nextRetain := a.clock.Now().Add(retainEvery)
	for {
		now := a.clock.Now()
		wait := nextFlush.Sub(now)
		if d := nextRetain.Sub(now); d < wait {
			wait = d
		}
		if wait < 0 {
			wait = 0
		}
		select {
		case <-a.stop:
			return
		case <-a.clock.After(wait):
			now = a.clock.Now()
			if !now.Before(nextFlush) {
				a.flush(context.Background())
				nextFlush = a.clock.Now().Add(flushEvery)
			}
			if !now.Before(nextRetain) {
				a.prune()
				nextRetain = a.clock.Now().Add(retainEvery)
			}
		}
	}
}

func (a *App) worker() {
	defer a.wg.Done()
	for {
		ev, ok := a.queue.Pop()
		if !ok {
			return
		}
		a.metrics.QueueDepth.Set(float64(a.queue.Depth()))
		ctx := a.ctx
		if ctx == nil {
			ctx = context.Background()
		}
		if err := a.store.InsertEvent(ctx, ev); err != nil {
			a.metrics.EventsSkipped.Inc()
			a.log.Info("event dropped", "key_id", ev.KeyID)
			continue
		}
		out := a.engine.Observe(ev)
		if err := a.store.SaveBaseline(ctx, out.Baseline); err != nil {
			a.metrics.EventsSkipped.Inc()
		}
		a.state.SetDryRun(ev.KeyID, out.Baseline.DryRunArmed, out.Baseline.DryRunBlocked)
		for _, d := range out.Detections {
			if err := a.store.InsertDetection(ctx, d); err != nil {
				a.metrics.EventsSkipped.Inc()
			}
		}
		for _, inc := range out.Incidents {
			var err error
			if inc.IsNew {
				err = a.store.InsertIncident(ctx, inc.KeyID, inc.Rule, inc.Opened, inc.Last)
			} else {
				err = a.store.TouchIncident(ctx, inc.KeyID, inc.Rule, inc.Opened, inc.Last)
			}
			if err != nil {
				a.metrics.EventsSkipped.Inc()
			}
		}
		if len(out.Alerts) > 0 {
			sender := alert.Sender{
				Now: func() time.Time { return a.clock.Now() },
				Destinations: func() []model.AlertDestination {
					list, err := a.svc.Alerts(ctx)
					if err != nil {
						return nil
					}
					return list
				},
			}
			for _, al := range out.Alerts {
				if k, ok := a.state.Key(al.KeyID); ok {
					al.KeyName = k.Name
				}
				if err := sender.Send(ctx, al); err != nil {
					a.metrics.AlertsFailed.Inc()
				} else {
					a.metrics.AlertsSent.Inc()
				}
			}
		}
		if out.DryRunTrip {
			_ = a.store.InsertAudit(ctx, model.AuditEntry{
				Time: a.clock.Now(), Actor: "system", Action: "auto_disable_dry_run", Target: ev.KeyID,
				Before: "", After: "would_disable", IP: ev.IP,
			})
		}
		if out.DisableKey {
			if err := a.store.UpdateKeyStatus(ctx, ev.KeyID, model.StatusDisabled, nil); err != nil {
				a.metrics.EventsSkipped.Inc()
				continue
			}
			if cur, ok := a.state.Key(ev.KeyID); ok {
				cur.Status = model.StatusDisabled
				a.state.PutKey(cur)
			}
			a.engine.NoteStatus(ev.KeyID, model.StatusDisabled, time.Time{})
			_ = a.store.InsertAudit(ctx, model.AuditEntry{
				Time: a.clock.Now(), Actor: "system", Action: "key.auto_disable", Target: ev.KeyID,
				Before: model.StatusActive, After: model.StatusDisabled, IP: ev.IP,
			})
		}
	}
}

func (a *App) flush(ctx context.Context) {
	rows := a.state.DirtySpend()
	if len(rows) == 0 {
		return
	}
	if err := a.saveSpend(ctx, rows); err != nil {
		a.state.NoteFlush(false, a.clock.Now())
		a.metrics.FlushFailures.Inc()
		if a.state.FlushFailing() {
			a.metrics.SpendDegraded.Set(1)
		}
		return
	}
	a.state.AckSpend(rows)
	a.state.NoteFlush(true, a.clock.Now())
	a.metrics.SpendDegraded.Set(0)
}

func (a *App) prune() {
	now := a.clock.Now()
	ev := a.cfg.EventRetention
	if ev <= 0 {
		ev = 14 * 24 * time.Hour
	}
	det := a.cfg.DetectionRetention
	if det <= 0 {
		det = 90 * 24 * time.Hour
	}
	if err := a.store.Prune(a.ctx, now.Add(-ev), now.Add(-det)); err != nil {
		a.log.Info("retention failed")
	}
}

// Close stops listeners, drains events, and flushes spend.
// The worker finishes stored events before the process context is cancelled,
// so a shutdown flush still sees the counters those events changed.
func (a *App) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if a.proxySrv != nil {
		_ = a.proxySrv.Shutdown(ctx)
	}
	if a.adminSrv != nil {
		_ = a.adminSrv.Shutdown(ctx)
	}
	if a.queue != nil {
		a.queue.Close()
	}
	if a.stop != nil {
		a.stopOnce.Do(func() { close(a.stop) })
	}
	a.wg.Wait()
	a.flush(context.Background())
	if a.cancel != nil {
		a.cancel()
	}
	if a.closeGeo != nil {
		_ = a.closeGeo()
	}
	if a.store != nil {
		return a.store.Close()
	}
	return nil
}

func (a *App) ProxyURL() string {
	if a.proxyLn == nil {
		return ""
	}
	return "http://" + a.proxyLn.Addr().String()
}

func (a *App) AdminURL() string {
	if a.adminLn == nil {
		return ""
	}
	if a.adminLn.Addr().Network() == "unix" {
		return "unix://" + a.adminLn.Addr().String()
	}
	return "http://" + a.adminLn.Addr().String()
}

func (a *App) AdminListenAddr() string {
	if a.adminLn == nil {
		return ""
	}
	return a.adminLn.Addr().String()
}

func listen(addr string) (net.Listener, error) {
	if strings.HasPrefix(addr, "unix://") || strings.HasPrefix(addr, "/") {
		path := strings.TrimPrefix(addr, "unix://")
		_ = os.Remove(path)
		return net.Listen("unix", path)
	}
	return net.Listen("tcp", addr)
}

type promAdapter struct{ m *metrics.Metrics }

func (p promAdapter) Request(code, profile string) {
	p.m.Requests.WithLabelValues(code, profile).Inc()
}
func (p promAdapter) Observe(profile string, seconds float64) {
	p.m.Duration.WithLabelValues(profile).Observe(seconds)
}
func (p promAdapter) Dropped(n int) { p.m.EventsDropped.Add(float64(n)) }
