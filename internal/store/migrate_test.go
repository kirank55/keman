package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/kirank55/keman/internal/model"
)

// A database created by the beta has no preset column. Opening it adds one
// and keeps the rows it already had.
func TestOpenAddsPresetToBetaDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keman.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE upstreams (
  id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, protocol TEXT NOT NULL, profile TEXT NOT NULL,
  host TEXT NOT NULL, port INTEGER NOT NULL, tls INTEGER NOT NULL,
  insecure_skip_verify INTEGER NOT NULL DEFAULT 0, server_name TEXT NOT NULL DEFAULT '',
  path_allowlist TEXT NOT NULL DEFAULT '', inject_usage INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
INSERT INTO upstreams (id, name, protocol, profile, host, port, tls, created_at)
  VALUES ('up_old', 'openai', 'http', 'openai', 'api.openai.com', 443, 1, '2026-10-01T00:00:00Z');`)
	db.Close()
	if err != nil {
		t.Fatal(err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	if err := s.InsertUpstream(ctx, model.Upstream{ID: "up_new", Name: "groq", Protocol: "http", Profile: "openai", Preset: "groq", Host: "api.groq.com", Port: 443, TLS: true, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	ups, err := s.ListUpstreams(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, u := range ups {
		got[u.ID] = u.Preset
	}
	if len(got) != 2 || got["up_old"] != "" || got["up_new"] != "groq" {
		t.Fatalf("%v", got)
	}
	s.Close()
	again, err := Open(path)
	if err != nil {
		t.Fatalf("reopening a migrated database: %v", err)
	}
	again.Close()
}
