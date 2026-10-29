package admin

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/kirank55/keman/internal/cryptoenc"
	"github.com/kirank55/keman/internal/model"
)

func presetService(t *testing.T) *Service {
	t.Helper()
	svc, _ := lifecycleService(t, 0)
	box, err := cryptoenc.NewBox(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	svc.Box = box
	return svc
}

func TestPresetFillsUpstream(t *testing.T) {
	svc := presetService(t)
	ctx := context.Background()
	u, err := svc.CreateUpstreamFrom(ctx, UpstreamRequest{Upstream: model.Upstream{Preset: "Groq"}}, "t", "")
	if err != nil {
		t.Fatal(err)
	}
	if u.Name != "groq" || u.Preset != "groq" || u.Profile != "openai" || u.Host != "api.groq.com" || u.Port != 443 || !u.TLS || !u.InjectUsage {
		t.Fatalf("%+v", u)
	}
	if len(u.PathAllowlist) == 0 || u.PathAllowlist[0] != "POST /openai/v1/chat/completions" {
		t.Fatalf("paths %v", u.PathAllowlist)
	}
	off := false
	mock, err := svc.CreateUpstreamFrom(ctx, UpstreamRequest{
		Upstream: model.Upstream{Name: "mistral-mock", Preset: "mistral", Host: "127.0.0.1", Port: 9000, PathAllowlist: []string{"POST /v1/chat/completions"}},
		TLS:      &off,
	}, "t", "")
	if err != nil {
		t.Fatal(err)
	}
	if mock.TLS || mock.Host != "127.0.0.1" || mock.Port != 9000 || len(mock.PathAllowlist) != 1 || mock.InjectUsage {
		t.Fatalf("overrides were not kept: %+v", mock)
	}
}

func TestPresetErrors(t *testing.T) {
	svc := presetService(t)
	ctx := context.Background()
	var op *OpError
	if _, err := svc.CreateUpstreamFrom(ctx, UpstreamRequest{Upstream: model.Upstream{Preset: "nope"}}, "t", ""); !errors.As(err, &op) || op.Status != 400 {
		t.Fatalf("unknown preset: %v", err)
	}
	if _, err := svc.CreateUpstreamFrom(ctx, UpstreamRequest{Upstream: model.Upstream{Preset: "stripe", Profile: "openai"}}, "t", ""); !errors.As(err, &op) || op.Status != 400 {
		t.Fatalf("profile mismatch: %v", err)
	}
	if _, err := svc.CreateUpstreamFrom(ctx, UpstreamRequest{Upstream: model.Upstream{Name: "x", Profile: "generic", Host: "h", Port: 443}}, "t", ""); err == nil {
		t.Fatal("a generic upstream without a preset still needs paths")
	}
}

func TestCredentialAuthComesFromPreset(t *testing.T) {
	svc := presetService(t)
	ctx := context.Background()
	mk := func(p string) model.Upstream {
		u, err := svc.CreateUpstreamFrom(ctx, UpstreamRequest{Upstream: model.Upstream{Preset: p}}, "t", "")
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	cases := []struct {
		up     model.Upstream
		style  string
		header string
	}{
		{mk("anthropic"), model.AuthHeader, "x-api-key: {key}"},
		{mk("postmark"), model.AuthHeader, "X-Postmark-Server-Token: {key}"},
		{mk("linear"), model.AuthHeader, "Authorization: {key}"},
		{mk("groq"), model.AuthHeader, "Authorization: Bearer {key}"},
	}
	for _, c := range cases {
		cred, err := svc.CreateCredential(ctx, model.Credential{UpstreamID: c.up.ID, Name: c.up.Name + "-main"}, "secret", "t", "")
		if err != nil {
			t.Fatal(err)
		}
		if cred.AuthStyle != c.style || cred.HeaderTemplate != c.header {
			t.Fatalf("%s: %s %q", c.up.Name, cred.AuthStyle, cred.HeaderTemplate)
		}
	}
	custom, err := svc.CreateCredential(ctx, model.Credential{UpstreamID: cases[0].up.ID, Name: "custom", HeaderTemplate: "Authorization: Bearer {key}"}, "s", "t", "")
	if err != nil || custom.AuthStyle != model.AuthHeader || custom.HeaderTemplate != "Authorization: Bearer {key}" {
		t.Fatalf("an explicit template was replaced: %+v %v", custom, err)
	}
	plain, err := svc.CreateCredential(ctx, model.Credential{UpstreamID: "up", Name: "no-preset"}, "s", "t", "")
	if err != nil || plain.HeaderTemplate != "Authorization: Bearer {key}" {
		t.Fatalf("no preset: %+v %v", plain, err)
	}
}

func TestTwilioCredentialNeedsSIDAndToken(t *testing.T) {
	svc := presetService(t)
	ctx := context.Background()
	up, err := svc.CreateUpstreamFrom(ctx, UpstreamRequest{Upstream: model.Upstream{Preset: "twilio"}}, "t", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateCredential(ctx, model.Credential{UpstreamID: up.ID, Name: "a"}, "token-only", "t", ""); err == nil {
		t.Fatal("accepted a Basic secret without user:password or a username")
	}
	pair, err := svc.CreateCredential(ctx, model.Credential{UpstreamID: up.ID, Name: "b"}, "AC123:token", "t", "")
	if err != nil || pair.AuthStyle != model.AuthBasic || !pair.SecretIsUserPass {
		t.Fatalf("%+v %v", pair, err)
	}
	named, err := svc.CreateCredential(ctx, model.Credential{UpstreamID: up.ID, Name: "c", BasicUsername: "AC123"}, "token", "t", "")
	if err != nil || named.SecretIsUserPass || named.BasicUsername != "AC123" {
		t.Fatalf("%+v %v", named, err)
	}
}
