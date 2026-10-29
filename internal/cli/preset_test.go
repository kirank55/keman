package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/kirank55/keman/internal/preset"
	"github.com/kirank55/keman/internal/scan"
)

func TestUpstreamPresetsNeedsNoServer(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"upstream", "presets"}, nil, nil, &stdout, &stderr); code != 0 {
		t.Fatalf("%d %s", code, stderr.String())
	}
	for _, p := range preset.All() {
		if !strings.Contains(stdout.String(), p.Name) || !strings.Contains(stdout.String(), p.Host) {
			t.Fatalf("%s missing:\n%s", p.Name, stdout.String())
		}
	}
}

func TestCanaryNamesFollowPreset(t *testing.T) {
	cases := []struct {
		up                 upstreamInfo
		key, url, basePath string
	}{
		{upstreamInfo{Preset: "groq", Profile: "openai"}, "GROQ_API_KEY", "GROQ_BASE_URL", "/openai/v1"},
		{upstreamInfo{Preset: "stripe", Profile: "generic"}, "STRIPE_SECRET_KEY", "STRIPE_BASE_URL", ""},
		{upstreamInfo{Preset: "github", Profile: "generic"}, "GITHUB_TOKEN", "GITHUB_BASE_URL", ""},
		{upstreamInfo{Profile: "openai", Host: "openrouter.ai"}, "OPENROUTER_API_KEY", "OPENROUTER_BASE_URL", "/api/v1"},
		{upstreamInfo{Profile: "generic", Name: "my api"}, "MY_API_API_KEY", "MY_API_BASE_URL", ""},
	}
	for _, c := range cases {
		key, url, path := canaryNames(c.up)
		if key != c.key || url != c.url || path != c.basePath {
			t.Errorf("%+v: %s %s %q", c.up, key, url, path)
		}
	}
}

func TestScanAdviceUsesPreset(t *testing.T) {
	var out bytes.Buffer
	c := &cmd{stdout: &out}
	found := scan.Line("GROQ_API_KEY=gs" + "k_" + strings.Repeat("a1B2", 13))
	c.printScan(scan.Distinct(found), len(found))
	for _, want := range []string{
		"keman upstream add --preset groq",
		"keman credential add --upstream groq --name groq-main --secret-env GROQ_API_KEY",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q:\n%s", want, out.String())
		}
	}
}
