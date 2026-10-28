package admin

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kirank55/keman/internal/clock"
	"github.com/kirank55/keman/internal/exposure"
	"github.com/kirank55/keman/internal/model"
	"github.com/kirank55/keman/internal/state"
	"github.com/kirank55/keman/internal/store"
)

func lifecycleService(t *testing.T, ttl time.Duration) (*Service, *clock.Fake) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "k.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	clk := clock.NewFake(time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC))
	mem := state.New(clk, 60, time.Second)
	mem.PutUpstream(model.Upstream{ID: "up", Name: "openai", Profile: "openai", Host: "api.openai.com", Port: 443})
	mem.PutCredential(model.Credential{ID: "cred", UpstreamID: "up", Name: "primary"})
	return &Service{Store: st, State: mem, Clock: clk, DefaultTTL: ttl}, clk
}

func TestSetClientName(t *testing.T) {
	svc, _ := lifecycleService(t, 0)
	ctx := context.Background()
	ip, name, err := svc.SetClientName(ctx, " 203.0.113.8 ", " office ", "admin", "127.0.0.1")
	if err != nil || ip != "203.0.113.8" || name != "office" {
		t.Fatalf("%s %s %v", ip, name, err)
	}
	got, err := svc.Store.ClientNames(ctx)
	if err != nil || got["203.0.113.8"] != "office" {
		t.Fatalf("%v %v", got, err)
	}
	if _, _, err := svc.SetClientName(ctx, "nope", "x", "admin", ""); err == nil {
		t.Fatal("accepted a bad address")
	}
	if _, _, err := svc.SetClientName(ctx, "203.0.113.8", "bad\nname", "admin", ""); err == nil {
		t.Fatal("accepted a control character")
	}
	if _, _, err := svc.SetClientName(ctx, "203.0.113.8", strings.Repeat("a", 33), "admin", ""); err == nil {
		t.Fatal("accepted a long name")
	}
	if _, _, err := svc.SetClientName(ctx, "203.0.113.8", " ", "admin", ""); err != nil {
		t.Fatal(err)
	}
	got, err = svc.Store.ClientNames(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got["203.0.113.8"]; ok {
		t.Fatalf("name not cleared: %v", got)
	}
	rows, err := svc.Store.ListAudit(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) < 2 || rows[0].Action != "client.name" || rows[0].Target != "203.0.113.8" {
		t.Fatalf("%+v", rows)
	}
}

func TestCreateKeyGetsDefaultExpiry(t *testing.T) {
	svc, clk := lifecycleService(t, 90*24*time.Hour)
	ctx := context.Background()
	_, k, err := svc.CreateKey(ctx, "cred", "laptop", "", nil, false, "t", "")
	if err != nil {
		t.Fatal(err)
	}
	if k.ExpiresAt == nil || !k.ExpiresAt.Equal(clk.Now().Add(90*24*time.Hour)) {
		t.Fatalf("expiry %v", k.ExpiresAt)
	}
	_, never, err := svc.CreateKey(ctx, "cred", "build", "", nil, true, "t", "")
	if err != nil || never.ExpiresAt != nil {
		t.Fatalf("no_expiry: %v %v", never.ExpiresAt, err)
	}
	_, canary, err := svc.CreateKey(ctx, "cred", "decoy", model.KindCanary, nil, false, "t", "")
	if err != nil || canary.ExpiresAt != nil {
		t.Fatalf("canary expiry: %v %v", canary.ExpiresAt, err)
	}
	past := clk.Now().Add(-time.Minute)
	if _, _, err := svc.CreateKey(ctx, "cred", "old", "", &past, false, "t", ""); err == nil {
		t.Fatal("accepted an expiry in the past")
	}
}

func TestRotateKeepsPolicyAndRetiresOldKey(t *testing.T) {
	svc, clk := lifecycleService(t, 30*24*time.Hour)
	ctx := context.Background()
	_, old, err := svc.CreateKey(ctx, "cred", "laptop", "", nil, false, "t", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.SetPolicy(ctx, old.ID, PolicyInput{CIDRs: []string{"10.0.0.0/8"}}, "t", ""); err != nil {
		t.Fatal(err)
	}
	rot, err := svc.RotateKey(ctx, old.ID, 2*time.Hour, "t", "")
	if err != nil {
		t.Fatal(err)
	}
	if rot.Token == "" || rot.New.ID == old.ID || rot.New.Name != "laptop" {
		t.Fatalf("new key %+v", rot.New)
	}
	if p, ok := svc.State.Policy(rot.New.ID); !ok || len(p.CIDRAllowlist) != 1 {
		t.Fatalf("policy not copied: %+v", p)
	}
	cur, _ := svc.State.Key(old.ID)
	if cur.Name != "laptop (rotated)" || cur.ExpiresAt == nil || !cur.ExpiresAt.Equal(clk.Now().Add(2*time.Hour)) {
		t.Fatalf("old key %+v", cur)
	}

	now, err := svc.RotateKey(ctx, rot.New.ID, 0, "t", "")
	if err != nil {
		t.Fatal(err)
	}
	if now.Old.Status != model.StatusRevoked {
		t.Fatalf("zero grace left the key %s", now.Old.Status)
	}
	if _, err := svc.RotateKey(ctx, rot.New.ID, time.Hour, "t", ""); err == nil {
		t.Fatal("rotated a revoked key")
	}
}

func TestSetExpiryAndExposureInKeyList(t *testing.T) {
	svc, clk := lifecycleService(t, 0)
	ctx := context.Background()
	_, k, err := svc.CreateKey(ctx, "cred", "laptop", "", nil, false, "t", "")
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{Service: svc}
	views := h.keyViews(ctx)
	got := views[0]["exposure"].([]exposure.Finding)
	if len(got) != 2 || got[0].Code != exposure.CodeNetworkOpen || got[1].Code != exposure.CodeNoExpiry {
		t.Fatalf("%+v", got)
	}
	at := clk.Now().Add(30 * 24 * time.Hour)
	if _, err := svc.SetExpiry(ctx, k.ID, &at, "t", ""); err != nil {
		t.Fatal(err)
	}
	views = h.keyViews(ctx)
	got = views[0]["exposure"].([]exposure.Finding)
	if len(got) != 1 || got[0].Code != exposure.CodeNetworkOpen {
		t.Fatalf("after expiry %+v", got)
	}
}
