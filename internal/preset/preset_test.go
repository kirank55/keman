package preset

import (
	"os"
	"strings"
	"testing"

	"github.com/kirank55/keman/internal/headers"
	"github.com/kirank55/keman/internal/model"
	"github.com/kirank55/keman/internal/pathmatch"
	"github.com/kirank55/keman/internal/profile"
)

func TestPresetsAreValid(t *testing.T) {
	for _, p := range All() {
		if !profile.Valid(p.Profile) {
			t.Errorf("%s: profile %q", p.Name, p.Profile)
		}
		if p.Host == "" || p.Port != 443 || !p.TLS {
			t.Errorf("%s: host %q port %d tls %v", p.Name, p.Host, p.Port, p.TLS)
		}
		if p.Profile == profile.Generic && len(p.Paths) == 0 {
			t.Errorf("%s: a generic preset needs paths", p.Name)
		}
		if _, err := pathmatch.ParseList(strings.Join(p.Paths, "\n")); err != nil {
			t.Errorf("%s: %v", p.Name, err)
		}
		switch p.Auth {
		case model.AuthHeader:
			if headers.TemplateHeaderName(p.Header) == "" {
				t.Errorf("%s: header template %q", p.Name, p.Header)
			}
		case model.AuthBasic:
		default:
			t.Errorf("%s: auth %q", p.Name, p.Auth)
		}
		if p.Env == "" || p.Title == "" {
			t.Errorf("%s: env %q title %q", p.Name, p.Env, p.Title)
		}
		if p.BasePath != "" && (!strings.HasPrefix(p.BasePath, "/") || strings.HasSuffix(p.BasePath, "/")) {
			t.Errorf("%s: base path %q", p.Name, p.BasePath)
		}
		if got, ok := Get(strings.ToUpper(p.Name)); !ok || got.Name != p.Name {
			t.Errorf("%s: Get is not case-insensitive", p.Name)
		}
	}
}

// The SDK base URL must reach an allowed path, or the preset is unusable.
func TestBasePathIsAllowed(t *testing.T) {
	for _, p := range All() {
		rules, _ := pathmatch.ParseList(strings.Join(p.Paths, "\n"))
		if len(rules) == 0 {
			rules = profile.Builtin(p.Profile)
		}
		ok := false
		for _, r := range rules {
			if strings.HasPrefix(r.Pattern, p.BasePath+"/") {
				ok = true
				break
			}
		}
		if !ok {
			t.Errorf("%s: no allowed path under base path %q", p.Name, p.BasePath)
		}
	}
}

func TestReadmeTableIsCurrent(t *testing.T) {
	b, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	i, j := strings.Index(s, TableStart), strings.Index(s, TableEnd)
	if i < 0 || j < i {
		t.Fatalf("README.md needs %s and %s around the platform table", TableStart, TableEnd)
	}
	got := strings.TrimSpace(s[i+len(TableStart) : j])
	want := strings.TrimSpace(Markdown())
	if got != want {
		t.Fatalf("README.md platform table is out of date. Replace it with:\n\n%s", want)
	}
}
