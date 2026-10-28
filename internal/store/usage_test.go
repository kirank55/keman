package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/kirank55/keman/internal/model"
)

func TestKeyUsageGroupsClients(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "keman.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	later := time.Date(2026, 10, 27, 16, 58, 0, 0, time.UTC)
	earlier := later.Add(-time.Minute)
	cost := int64(1_500)
	events := []model.Event{
		{
			Time: earlier, KeyID: "k", Kind: model.KindStandard, IP: "127.0.0.1",
			Operation: "POST /api/v1/chat/completions", Status: 200, LatencyMS: 1885,
			TokensIn: 10, TokensOut: 4, Model: "openai/gpt-4o-mini", CostMicro: &cost, Profile: "openai",
		},
		{
			Time: later, KeyID: "k", Kind: model.KindStandard, IP: "203.0.113.8", Country: "US", ASN: 15169,
			Operation: "POST /api/v1/chat/completions", Status: 200, LatencyMS: 400,
			TokensIn: 20, TokensOut: 6, Model: "openai/gpt-4o-mini", Profile: "openai",
		},
		{
			Time: later, KeyID: "other", Kind: model.KindStandard, IP: "198.51.100.1",
			Operation: "POST /api/v1/chat/completions", Status: 200, Profile: "openai",
		},
	}
	for _, ev := range events {
		if err := s.InsertEvent(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.KeyUsage(ctx, "k", 12)
	if err != nil {
		t.Fatal(err)
	}
	if got.Requests != 2 || got.TokensIn != 30 || got.TokensOut != 10 || got.CostMicro != 1_500 || got.Priced != 1 {
		t.Fatalf("%+v", got)
	}
	if got.LastSeen == nil || !got.LastSeen.Equal(later) {
		t.Fatalf("last %v", got.LastSeen)
	}
	if len(got.Clients) != 2 || got.Clients[0].IP != "203.0.113.8" || got.Clients[0].Country != "US" || got.Clients[0].ASN != 15169 {
		t.Fatalf("%+v", got.Clients)
	}
	if len(got.Recent) != 2 || got.Recent[0].IP != "203.0.113.8" || got.Recent[1].IP != "127.0.0.1" {
		t.Fatalf("%+v", got.Recent)
	}
	if got.Recent[1].CostMicro == nil || *got.Recent[1].CostMicro != 1_500 {
		t.Fatalf("%+v", got.Recent[1])
	}
	if len(got.Models) != 1 || got.Models[0].Model != "openai/gpt-4o-mini" || got.Models[0].Requests != 2 {
		t.Fatalf("%+v", got.Models)
	}
}
