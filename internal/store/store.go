// Package store is the SQLite adapter. The request path does not call it.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/kirank55/keman/internal/model"
)

const schema = `
CREATE TABLE IF NOT EXISTS schema_meta (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  wrapped_dek BLOB NOT NULL,
  dek_nonce BLOB NOT NULL,
  kek_version INTEGER NOT NULL,
  admin_token_hash BLOB NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS upstreams (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  protocol TEXT NOT NULL,
  profile TEXT NOT NULL,
  host TEXT NOT NULL,
  port INTEGER NOT NULL,
  tls INTEGER NOT NULL,
  insecure_skip_verify INTEGER NOT NULL DEFAULT 0,
  server_name TEXT NOT NULL DEFAULT '',
  path_allowlist TEXT NOT NULL DEFAULT '',
  inject_usage INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS credentials (
  id TEXT PRIMARY KEY,
  upstream_id TEXT NOT NULL,
  name TEXT NOT NULL UNIQUE,
  auth_style TEXT NOT NULL,
  header_template TEXT NOT NULL DEFAULT '',
  basic_username TEXT NOT NULL DEFAULT '',
  secret_is_userpass INTEGER NOT NULL DEFAULT 0,
  ciphertext BLOB NOT NULL,
  nonce BLOB NOT NULL,
  key_version INTEGER NOT NULL,
  last4 TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS virtual_keys (
  id TEXT PRIMARY KEY,
  credential_id TEXT NOT NULL,
  name TEXT NOT NULL DEFAULT '',
  secret_hash BLOB NOT NULL,
  kind TEXT NOT NULL,
  status TEXT NOT NULL,
  expires_at TEXT,
  auto_disable_paused_until TEXT,
  dry_run_armed INTEGER NOT NULL DEFAULT 0,
  dry_run_blocked INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS policies (
  virtual_key_id TEXT PRIMARY KEY,
  mode TEXT NOT NULL,
  rpm INTEGER,
  daily_cap_micro INTEGER,
  monthly_cap_micro INTEGER,
  path_allowlist TEXT NOT NULL DEFAULT '',
  model_allowlist TEXT NOT NULL DEFAULT '',
  cidr_allowlist TEXT NOT NULL DEFAULT '',
  country_allowlist TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS spend_counters (
  virtual_key_id TEXT NOT NULL,
  period TEXT NOT NULL,
  micro INTEGER NOT NULL,
  PRIMARY KEY (virtual_key_id, period)
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  virtual_key_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  ip TEXT NOT NULL,
  country TEXT NOT NULL,
  asn INTEGER NOT NULL,
  operation TEXT NOT NULL,
  status INTEGER NOT NULL,
  latency_ms INTEGER NOT NULL,
  req_bytes INTEGER NOT NULL,
  resp_bytes INTEGER NOT NULL,
  tokens_in INTEGER NOT NULL,
  tokens_out INTEGER NOT NULL,
  cached_tokens INTEGER NOT NULL,
  cache_write_tokens INTEGER NOT NULL,
  cost_micro INTEGER,
  cost_estimated INTEGER NOT NULL,
  model TEXT NOT NULL,
  blocked_code TEXT NOT NULL,
  profile TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_key_ts ON events(virtual_key_id, ts);
CREATE TABLE IF NOT EXISTS baselines (
  virtual_key_id TEXT PRIMARY KEY,
  first_seen TEXT NOT NULL,
  request_count INTEGER NOT NULL,
  countries_json TEXT NOT NULL,
  asns_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS detections (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  virtual_key_id TEXT NOT NULL,
  rule TEXT NOT NULL,
  severity TEXT NOT NULL,
  evidence_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_det_key_ts ON detections(virtual_key_id, ts);
CREATE TABLE IF NOT EXISTS incidents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  virtual_key_id TEXT NOT NULL,
  rule TEXT NOT NULL,
  opened_at TEXT NOT NULL,
  last_fired_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alert_destinations (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  url TEXT NOT NULL,
  secret_ciphertext BLOB,
  secret_nonce BLOB,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL,
  before_json TEXT NOT NULL,
  after_json TEXT NOT NULL,
  ip TEXT NOT NULL
);
`

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetConnMaxLifetime(0)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

type Meta struct {
	WrappedDEK []byte
	DEKNonce   []byte
	KEKVersion int
	AdminHash  []byte
}

func (s *Store) LoadMeta(ctx context.Context) (Meta, bool, error) {
	var m Meta
	err := s.db.QueryRowContext(ctx, `SELECT wrapped_dek, dek_nonce, kek_version, admin_token_hash FROM schema_meta WHERE id = 1`).
		Scan(&m.WrappedDEK, &m.DEKNonce, &m.KEKVersion, &m.AdminHash)
	if errors.Is(err, sql.ErrNoRows) {
		return Meta{}, false, nil
	}
	if err != nil {
		return Meta{}, false, err
	}
	return m, true, nil
}

func (s *Store) Init(ctx context.Context, m Meta, now time.Time) error {
	_, ok, err := s.LoadMeta(ctx)
	if err != nil {
		return err
	}
	if ok {
		return fmt.Errorf("database is already initialized")
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO schema_meta (id, wrapped_dek, dek_nonce, kek_version, admin_token_hash, created_at) VALUES (1, ?, ?, ?, ?, ?)`,
		m.WrappedDEK, m.DEKNonce, m.KEKVersion, m.AdminHash, fmtTime(now))
	return err
}

func (s *Store) UpdateMetaKeys(ctx context.Context, wrapped, nonce []byte, version int) error {
	_, err := s.db.ExecContext(ctx, `UPDATE schema_meta SET wrapped_dek = ?, dek_nonce = ?, kek_version = ? WHERE id = 1`, wrapped, nonce, version)
	return err
}

func (s *Store) UpdateAdminHash(ctx context.Context, hash []byte) error {
	_, err := s.db.ExecContext(ctx, `UPDATE schema_meta SET admin_token_hash = ? WHERE id = 1`, hash)
	return err
}

func (s *Store) InsertUpstream(ctx context.Context, u model.Upstream) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO upstreams (id, name, protocol, profile, host, port, tls, insecure_skip_verify, server_name, path_allowlist, inject_usage, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		u.ID, u.Name, u.Protocol, u.Profile, u.Host, u.Port, bit(u.TLS), bit(u.InsecureSkipVerify), u.ServerName, strings.Join(u.PathAllowlist, "\n"), bit(u.InjectUsage), fmtTime(u.CreatedAt))
	return err
}

func (s *Store) ListUpstreams(ctx context.Context) ([]model.Upstream, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, protocol, profile, host, port, tls, insecure_skip_verify, server_name, path_allowlist, inject_usage, created_at FROM upstreams ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Upstream
	for rows.Next() {
		var u model.Upstream
		var tls, insecure, inject int
		var paths, created string
		if err := rows.Scan(&u.ID, &u.Name, &u.Protocol, &u.Profile, &u.Host, &u.Port, &tls, &insecure, &u.ServerName, &paths, &inject, &created); err != nil {
			return nil, err
		}
		u.TLS = tls == 1
		u.InsecureSkipVerify = insecure == 1
		u.InjectUsage = inject == 1
		u.PathAllowlist = splitLines(paths)
		u.CreatedAt, _ = parseTime(created)
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) InsertCredential(ctx context.Context, c model.Credential) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO credentials (id, upstream_id, name, auth_style, header_template, basic_username, secret_is_userpass, ciphertext, nonce, key_version, last4, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.UpstreamID, c.Name, c.AuthStyle, c.HeaderTemplate, c.BasicUsername, bit(c.SecretIsUserPass), c.Ciphertext, c.Nonce, c.KeyVersion, c.Last4, fmtTime(c.CreatedAt), fmtTime(c.UpdatedAt))
	return err
}

func (s *Store) UpdateCredentialSecret(ctx context.Context, id string, ct, nonce []byte, version int, last4 string, now time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE credentials SET ciphertext = ?, nonce = ?, key_version = ?, last4 = ?, updated_at = ? WHERE id = ?`,
		ct, nonce, version, last4, fmtTime(now), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) ListCredentials(ctx context.Context) ([]model.Credential, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, upstream_id, name, auth_style, header_template, basic_username, secret_is_userpass, ciphertext, nonce, key_version, last4, created_at, updated_at FROM credentials ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Credential
	for rows.Next() {
		var c model.Credential
		var userpass int
		var created, updated string
		if err := rows.Scan(&c.ID, &c.UpstreamID, &c.Name, &c.AuthStyle, &c.HeaderTemplate, &c.BasicUsername, &userpass, &c.Ciphertext, &c.Nonce, &c.KeyVersion, &c.Last4, &created, &updated); err != nil {
			return nil, err
		}
		c.SecretIsUserPass = userpass == 1
		c.CreatedAt, _ = parseTime(created)
		c.UpdatedAt, _ = parseTime(updated)
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) InsertKey(ctx context.Context, k model.VirtualKey) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO virtual_keys (id, credential_id, name, secret_hash, kind, status, expires_at, auto_disable_paused_until, dry_run_armed, dry_run_blocked, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		k.ID, k.CredentialID, k.Name, k.SecretHash, k.Kind, k.Status, fmtTimePtr(k.ExpiresAt), fmtTimePtr(k.PausedUntil), bit(k.DryRunArmed), k.DryRunBlocked, fmtTime(k.CreatedAt))
	return err
}

func (s *Store) ListKeys(ctx context.Context) ([]model.VirtualKey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, credential_id, name, secret_hash, kind, status, expires_at, auto_disable_paused_until, dry_run_armed, dry_run_blocked, created_at FROM virtual_keys ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.VirtualKey
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanKey(rows rowScanner) (model.VirtualKey, error) {
	var k model.VirtualKey
	var expires, paused, created sql.NullString
	var armed int
	if err := rows.Scan(&k.ID, &k.CredentialID, &k.Name, &k.SecretHash, &k.Kind, &k.Status, &expires, &paused, &armed, &k.DryRunBlocked, &created); err != nil {
		return model.VirtualKey{}, err
	}
	k.DryRunArmed = armed == 1
	k.ExpiresAt = parseTimePtr(expires.String)
	k.PausedUntil = parseTimePtr(paused.String)
	k.CreatedAt, _ = parseTime(created.String)
	return k, nil
}

func (s *Store) UpdateKeyStatus(ctx context.Context, id, status string, paused *time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE virtual_keys SET status = ?, auto_disable_paused_until = ? WHERE id = ?`, status, fmtTimePtr(paused), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// UpdateKeyLifecycle sets a key's name and expiry. A nil expiry means it never expires.
func (s *Store) UpdateKeyLifecycle(ctx context.Context, id, name string, expires *time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE virtual_keys SET name = ?, expires_at = ? WHERE id = ?`, name, fmtTimePtr(expires), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// Activity is where a key was last used from, and how often rules fired on it.
type Activity struct {
	LastSeen   time.Time
	LastIP     string
	Country    string
	Detections int
}

// KeyActivity returns the newest event and the detection count since
// detectionsSince for every key that has either.
func (s *Store) KeyActivity(ctx context.Context, detectionsSince time.Time) (map[string]Activity, error) {
	out := map[string]Activity{}
	rows, err := s.db.QueryContext(ctx, `SELECT e.virtual_key_id, e.ts, e.ip, e.country FROM events e
		JOIN (SELECT virtual_key_id, MAX(id) AS id FROM events GROUP BY virtual_key_id) last ON last.id = e.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, ts string
		var a Activity
		if err := rows.Scan(&id, &ts, &a.LastIP, &a.Country); err != nil {
			return nil, err
		}
		a.LastSeen, _ = parseTime(ts)
		out[id] = a
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	drows, err := s.db.QueryContext(ctx, `SELECT virtual_key_id, COUNT(*) FROM detections WHERE ts >= ? GROUP BY virtual_key_id`, fmtTime(detectionsSince))
	if err != nil {
		return nil, err
	}
	defer drows.Close()
	for drows.Next() {
		var id string
		var n int
		if err := drows.Scan(&id, &n); err != nil {
			return nil, err
		}
		a := out[id]
		a.Detections = n
		out[id] = a
	}
	return out, drows.Err()
}

func (s *Store) UpsertPolicy(ctx context.Context, p model.Policy) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO policies (virtual_key_id, mode, rpm, daily_cap_micro, monthly_cap_micro, path_allowlist, model_allowlist, cidr_allowlist, country_allowlist, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(virtual_key_id) DO UPDATE SET mode = excluded.mode, rpm = excluded.rpm, daily_cap_micro = excluded.daily_cap_micro, monthly_cap_micro = excluded.monthly_cap_micro, path_allowlist = excluded.path_allowlist, model_allowlist = excluded.model_allowlist, cidr_allowlist = excluded.cidr_allowlist, country_allowlist = excluded.country_allowlist, updated_at = excluded.updated_at`,
		p.KeyID, p.Mode, nullInt(p.RPM), nullInt64(p.DailyCapMicro), nullInt64(p.MonthlyCapMicro),
		strings.Join(p.PathAllowlist, "\n"), strings.Join(p.ModelAllowlist, "\n"), strings.Join(p.CIDRAllowlist, "\n"), strings.Join(p.CountryAllowlist, "\n"), fmtTime(p.UpdatedAt))
	return err
}

func (s *Store) ListPolicies(ctx context.Context) ([]model.Policy, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT virtual_key_id, mode, rpm, daily_cap_micro, monthly_cap_micro, path_allowlist, model_allowlist, cidr_allowlist, country_allowlist, updated_at FROM policies`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Policy
	for rows.Next() {
		var p model.Policy
		var rpm, daily, monthly sql.NullInt64
		var paths, models, cidrs, countries, updated string
		if err := rows.Scan(&p.KeyID, &p.Mode, &rpm, &daily, &monthly, &paths, &models, &cidrs, &countries, &updated); err != nil {
			return nil, err
		}
		if rpm.Valid {
			v := int(rpm.Int64)
			p.RPM = &v
		}
		if daily.Valid {
			v := daily.Int64
			p.DailyCapMicro = &v
		}
		if monthly.Valid {
			v := monthly.Int64
			p.MonthlyCapMicro = &v
		}
		p.PathAllowlist = splitLines(paths)
		p.ModelAllowlist = splitLines(models)
		p.CIDRAllowlist = splitLines(cidrs)
		p.CountryAllowlist = splitLines(countries)
		p.UpdatedAt, _ = parseTime(updated)
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) LoadSpend(ctx context.Context) ([]model.SpendRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT virtual_key_id, period, micro FROM spend_counters`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.SpendRow
	for rows.Next() {
		var r model.SpendRow
		if err := rows.Scan(&r.KeyID, &r.Period, &r.Micro); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) SaveSpend(ctx context.Context, rows []model.SpendRow) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, r := range rows {
		if _, err := tx.ExecContext(ctx, `INSERT INTO spend_counters (virtual_key_id, period, micro) VALUES (?, ?, ?)
			ON CONFLICT(virtual_key_id, period) DO UPDATE SET micro = excluded.micro`, r.KeyID, r.Period, r.Micro); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) InsertEvent(ctx context.Context, ev model.Event) error {
	var cost any
	if ev.CostMicro != nil {
		cost = *ev.CostMicro
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO events (ts, virtual_key_id, kind, ip, country, asn, operation, status, latency_ms, req_bytes, resp_bytes, tokens_in, tokens_out, cached_tokens, cache_write_tokens, cost_micro, cost_estimated, model, blocked_code, profile) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		fmtTime(ev.Time), ev.KeyID, ev.Kind, ev.IP, ev.Country, ev.ASN, ev.Operation, ev.Status, ev.LatencyMS, ev.ReqBytes, ev.RespBytes, ev.TokensIn, ev.TokensOut, ev.CachedTokens, ev.CacheWriteTokens, cost, bit(ev.CostEstimated), ev.Model, ev.BlockedCode, ev.Profile)
	return err
}

func (s *Store) EventsSince(ctx context.Context, keyID string, since time.Time) ([]model.Event, error) {
	q := `SELECT ts, virtual_key_id, kind, ip, country, asn, operation, status, latency_ms, req_bytes, resp_bytes, tokens_in, tokens_out, cached_tokens, cache_write_tokens, cost_micro, cost_estimated, model, blocked_code, profile FROM events WHERE ts >= ?`
	args := []any{fmtTime(since)}
	if keyID != "" {
		q += ` AND virtual_key_id = ?`
		args = append(args, keyID)
	}
	q += ` ORDER BY ts ASC, id ASC`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Event
	for rows.Next() {
		var ev model.Event
		var ts string
		var cost sql.NullInt64
		var est int
		if err := rows.Scan(&ts, &ev.KeyID, &ev.Kind, &ev.IP, &ev.Country, &ev.ASN, &ev.Operation, &ev.Status, &ev.LatencyMS, &ev.ReqBytes, &ev.RespBytes, &ev.TokensIn, &ev.TokensOut, &ev.CachedTokens, &ev.CacheWriteTokens, &cost, &est, &ev.Model, &ev.BlockedCode, &ev.Profile); err != nil {
			return nil, err
		}
		ev.Time, _ = parseTime(ts)
		ev.CostEstimated = est == 1
		if cost.Valid {
			v := cost.Int64
			ev.CostMicro = &v
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

// UsageClient is one source address that has called with a virtual key.
type UsageClient struct {
	IP       string    `json:"ip"`
	Country  string    `json:"country,omitempty"`
	ASN      int       `json:"asn,omitempty"`
	Requests int       `json:"requests"`
	LastSeen time.Time `json:"last_seen"`
}

// UsageModel is token and cost totals for one model name.
type UsageModel struct {
	Model     string `json:"model"`
	Requests  int    `json:"requests"`
	TokensIn  int64  `json:"tokens_in"`
	TokensOut int64  `json:"tokens_out"`
	CostMicro int64  `json:"cost_microusd"`
	Priced    int    `json:"priced"`
}

// UsageRequest is one proxied call, newest first in KeyUsage.Recent.
type UsageRequest struct {
	Time          time.Time `json:"time"`
	IP            string    `json:"ip"`
	Country       string    `json:"country,omitempty"`
	ASN           int       `json:"asn,omitempty"`
	Operation     string    `json:"operation"`
	Status        int       `json:"status"`
	LatencyMS     int64     `json:"latency_ms"`
	Model         string    `json:"model,omitempty"`
	TokensIn      int64     `json:"tokens_in"`
	TokensOut     int64     `json:"tokens_out"`
	CostMicro     *int64    `json:"cost_microusd,omitempty"`
	CostEstimated bool      `json:"cost_estimated,omitempty"`
	BlockedCode   string    `json:"blocked_code,omitempty"`
}

// KeyUsage is request activity still kept for a virtual key.
type KeyUsage struct {
	Requests   int            `json:"requests"`
	TokensIn   int64          `json:"tokens_in"`
	TokensOut  int64          `json:"tokens_out"`
	Cached     int64          `json:"cached_tokens"`
	CacheWrite int64          `json:"cache_write_tokens"`
	CostMicro  int64          `json:"cost_microusd"`
	Priced     int            `json:"priced"`
	Estimated  int            `json:"estimated"`
	LastSeen   *time.Time     `json:"last_seen,omitempty"`
	Clients    []UsageClient  `json:"clients"`
	Models     []UsageModel   `json:"models"`
	Recent     []UsageRequest `json:"recent"`
}

// KeyUsage returns totals, client addresses, and the newest requests for a key.
// limit caps each of those lists. Events older than the retention window are already gone.
func (s *Store) KeyUsage(ctx context.Context, keyID string, limit int) (KeyUsage, error) {
	if limit <= 0 {
		limit = 12
	}
	var out KeyUsage
	out.Clients = []UsageClient{}
	out.Models = []UsageModel{}
	out.Recent = []UsageRequest{}
	var tin, tout, cached, cwrite, cost sql.NullInt64
	var priced, estimated sql.NullInt64
	var last sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*),
		COALESCE(SUM(tokens_in), 0), COALESCE(SUM(tokens_out), 0),
		COALESCE(SUM(cached_tokens), 0), COALESCE(SUM(cache_write_tokens), 0),
		COALESCE(SUM(cost_micro), 0),
		SUM(CASE WHEN cost_micro IS NULL THEN 0 ELSE 1 END),
		SUM(CASE WHEN cost_estimated = 1 THEN 1 ELSE 0 END),
		MAX(ts)
		FROM events WHERE virtual_key_id = ?`, keyID).Scan(
		&out.Requests, &tin, &tout, &cached, &cwrite, &cost, &priced, &estimated, &last)
	if err != nil {
		return KeyUsage{}, err
	}
	out.TokensIn, out.TokensOut = tin.Int64, tout.Int64
	out.Cached, out.CacheWrite = cached.Int64, cwrite.Int64
	out.CostMicro = cost.Int64
	out.Priced = int(priced.Int64)
	out.Estimated = int(estimated.Int64)
	if last.Valid && last.String != "" {
		if t, err := parseTime(last.String); err == nil {
			out.LastSeen = &t
		}
	}
	rows, err := s.db.QueryContext(ctx, `SELECT ip, country, asn, COUNT(*), MAX(ts)
		FROM events WHERE virtual_key_id = ?
		GROUP BY ip, country, asn
		ORDER BY COUNT(*) DESC, MAX(ts) DESC
		LIMIT ?`, keyID, limit)
	if err != nil {
		return KeyUsage{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var c UsageClient
		var ts string
		if err := rows.Scan(&c.IP, &c.Country, &c.ASN, &c.Requests, &ts); err != nil {
			return KeyUsage{}, err
		}
		c.LastSeen, _ = parseTime(ts)
		out.Clients = append(out.Clients, c)
	}
	if err := rows.Err(); err != nil {
		return KeyUsage{}, err
	}
	if err := rows.Close(); err != nil {
		return KeyUsage{}, err
	}
	mrows, err := s.db.QueryContext(ctx, `SELECT model, COUNT(*),
		COALESCE(SUM(tokens_in), 0), COALESCE(SUM(tokens_out), 0),
		COALESCE(SUM(cost_micro), 0),
		SUM(CASE WHEN cost_micro IS NULL THEN 0 ELSE 1 END)
		FROM events WHERE virtual_key_id = ?
		GROUP BY model
		ORDER BY COUNT(*) DESC, model
		LIMIT ?`, keyID, limit)
	if err != nil {
		return KeyUsage{}, err
	}
	defer mrows.Close()
	for mrows.Next() {
		var m UsageModel
		var priced int
		if err := mrows.Scan(&m.Model, &m.Requests, &m.TokensIn, &m.TokensOut, &m.CostMicro, &priced); err != nil {
			return KeyUsage{}, err
		}
		m.Priced = priced
		out.Models = append(out.Models, m)
	}
	if err := mrows.Err(); err != nil {
		return KeyUsage{}, err
	}
	rrows, err := s.db.QueryContext(ctx, `SELECT ts, ip, country, asn, operation, status, latency_ms, model, tokens_in, tokens_out, cost_micro, cost_estimated, blocked_code
		FROM events WHERE virtual_key_id = ?
		ORDER BY ts DESC, id DESC
		LIMIT ?`, keyID, limit)
	if err != nil {
		return KeyUsage{}, err
	}
	defer rrows.Close()
	for rrows.Next() {
		var r UsageRequest
		var ts string
		var cost sql.NullInt64
		var est int
		if err := rrows.Scan(&ts, &r.IP, &r.Country, &r.ASN, &r.Operation, &r.Status, &r.LatencyMS, &r.Model, &r.TokensIn, &r.TokensOut, &cost, &est, &r.BlockedCode); err != nil {
			return KeyUsage{}, err
		}
		r.Time, _ = parseTime(ts)
		r.CostEstimated = est == 1
		if cost.Valid {
			v := cost.Int64
			r.CostMicro = &v
		}
		out.Recent = append(out.Recent, r)
	}
	return out, rrows.Err()
}

func (s *Store) SaveBaseline(ctx context.Context, b model.Baseline) error {
	cj, err := json.Marshal(b.Countries)
	if err != nil {
		return err
	}
	aj, err := json.Marshal(b.ASNs)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO baselines (virtual_key_id, first_seen, request_count, countries_json, asns_json) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(virtual_key_id) DO UPDATE SET first_seen = excluded.first_seen, request_count = excluded.request_count, countries_json = excluded.countries_json, asns_json = excluded.asns_json`,
		b.KeyID, fmtTime(b.FirstSeen), b.RequestCount, string(cj), string(aj)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE virtual_keys SET dry_run_armed = ?, dry_run_blocked = ? WHERE id = ?`, bit(b.DryRunArmed), b.DryRunBlocked, b.KeyID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ListBaselines(ctx context.Context) ([]model.Baseline, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT virtual_key_id, first_seen, request_count, countries_json, asns_json FROM baselines`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Baseline
	for rows.Next() {
		var b model.Baseline
		var first, cj, aj string
		if err := rows.Scan(&b.KeyID, &first, &b.RequestCount, &cj, &aj); err != nil {
			return nil, err
		}
		b.FirstSeen, _ = parseTime(first)
		b.Countries = map[string]time.Time{}
		b.ASNs = map[int]time.Time{}
		if cj != "" && cj != "null" {
			_ = json.Unmarshal([]byte(cj), &b.Countries)
		}
		if aj != "" && aj != "null" {
			_ = json.Unmarshal([]byte(aj), &b.ASNs)
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *Store) InsertDetection(ctx context.Context, d model.Detection) error {
	ev, err := json.Marshal(d.Evidence)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO detections (ts, virtual_key_id, rule, severity, evidence_json) VALUES (?, ?, ?, ?, ?)`,
		fmtTime(d.Time), d.KeyID, d.Rule, d.Severity, string(ev))
	return err
}

func (s *Store) DetectionsSince(ctx context.Context, keyID string, since time.Time) ([]model.Detection, error) {
	q := `SELECT id, ts, virtual_key_id, rule, severity, evidence_json FROM detections WHERE ts >= ?`
	args := []any{fmtTime(since)}
	if keyID != "" {
		q += ` AND virtual_key_id = ?`
		args = append(args, keyID)
	}
	q += ` ORDER BY ts ASC, id ASC`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Detection
	for rows.Next() {
		var d model.Detection
		var ts, ev string
		if err := rows.Scan(&d.ID, &ts, &d.KeyID, &d.Rule, &d.Severity, &ev); err != nil {
			return nil, err
		}
		d.Time, _ = parseTime(ts)
		_ = json.Unmarshal([]byte(ev), &d.Evidence)
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) InsertIncident(ctx context.Context, keyID, rule string, opened, last time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO incidents (virtual_key_id, rule, opened_at, last_fired_at) VALUES (?, ?, ?, ?)`,
		keyID, rule, fmtTime(opened), fmtTime(last))
	return err
}

func (s *Store) TouchIncident(ctx context.Context, keyID, rule string, opened, last time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE incidents SET last_fired_at = ? WHERE virtual_key_id = ? AND rule = ? AND opened_at = ?`,
		fmtTime(last), keyID, rule, fmtTime(opened))
	return err
}

func (s *Store) OpenIncidents(ctx context.Context, since time.Time) ([]model.Incident, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, virtual_key_id, rule, opened_at, last_fired_at FROM incidents WHERE last_fired_at >= ?`, fmtTime(since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Incident
	for rows.Next() {
		var inc model.Incident
		var opened, last string
		if err := rows.Scan(&inc.ID, &inc.KeyID, &inc.Rule, &opened, &last); err != nil {
			return nil, err
		}
		inc.OpenedAt, _ = parseTime(opened)
		inc.LastFired, _ = parseTime(last)
		out = append(out, inc)
	}
	return out, rows.Err()
}

func (s *Store) InsertAlert(ctx context.Context, a model.AlertDestination) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO alert_destinations (id, kind, url, secret_ciphertext, secret_nonce, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		a.ID, a.Kind, a.URL, nil, nil, fmtTime(a.CreatedAt))
	return err
}

func (s *Store) InsertAlertSecret(ctx context.Context, a model.AlertDestination, ct, nonce []byte) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO alert_destinations (id, kind, url, secret_ciphertext, secret_nonce, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		a.ID, a.Kind, a.URL, ct, nonce, fmtTime(a.CreatedAt))
	return err
}

type AlertRow struct {
	ID         string
	Kind       string
	URL        string
	Ciphertext []byte
	Nonce      []byte
	CreatedAt  time.Time
}

func (s *Store) ListAlerts(ctx context.Context) ([]AlertRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, kind, url, secret_ciphertext, secret_nonce, created_at FROM alert_destinations ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AlertRow
	for rows.Next() {
		var a AlertRow
		var created string
		if err := rows.Scan(&a.ID, &a.Kind, &a.URL, &a.Ciphertext, &a.Nonce, &created); err != nil {
			return nil, err
		}
		a.CreatedAt, _ = parseTime(created)
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) InsertAudit(ctx context.Context, e model.AuditEntry) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit_log (ts, actor, action, target, before_json, after_json, ip) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		fmtTime(e.Time), e.Actor, e.Action, e.Target, e.Before, e.After, e.IP)
	return err
}

func (s *Store) ListAudit(ctx context.Context, limit int) ([]model.AuditEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, ts, actor, action, target, before_json, after_json, ip FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.AuditEntry
	for rows.Next() {
		var e model.AuditEntry
		var ts string
		if err := rows.Scan(&e.ID, &ts, &e.Actor, &e.Action, &e.Target, &e.Before, &e.After, &e.IP); err != nil {
			return nil, err
		}
		e.Time, _ = parseTime(ts)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) Prune(ctx context.Context, eventsBefore, detectionsBefore time.Time) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM events WHERE ts < ?`, fmtTime(eventsBefore)); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM detections WHERE ts < ?`, fmtTime(detectionsBefore))
	return err
}

func bit(v bool) int {
	if v {
		return 1
	}
	return 0
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func fmtTimePtr(t *time.Time) any {
	if t == nil || t.IsZero() {
		return nil
	}
	return fmtTime(*t)
}

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339Nano, s)
}

func parseTimePtr(s string) *time.Time {
	t, err := parseTime(s)
	if err != nil || t.IsZero() {
		return nil
	}
	return &t
}

func splitLines(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func nullInt(v *int) any {
	if v == nil {
		return nil
	}
	return *v
}

func nullInt64(v *int64) any {
	if v == nil {
		return nil
	}
	return *v
}
