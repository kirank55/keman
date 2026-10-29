package scan

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Test secrets are assembled at run time so this file never holds a
// string that a secret scanner (including this one) would flag.
func fake(prefix string, n int) string { return prefix + strings.Repeat("a1B2", n/4+1)[:n] }

func TestLineFindsEachProvider(t *testing.T) {
	cases := map[string]string{
		"anthropic":         fake("sk-ant-"+"api03-", 90),
		"openrouter":        "sk-or-" + "v1-" + strings.Repeat("0f", 32),
		"openai":            fake("sk-"+"proj-", 60),
		"stripe":            fake("sk_"+"live_", 30),
		"github":            fake("gh"+"p_", 36),
		"groq":              fake("gs"+"k_", 52),
		"xai":               fake("xa"+"i-", 80),
		"sendgrid":          "S" + "G." + fake("", 22) + "." + fake("", 43),
		"linear":            fake("lin_"+"api_", 40),
		"google_api":        "AI" + "za" + fake("", 35),
		"aws_access_key":    "AK" + "IA" + "ABCDEFGHIJKLMNOP",
		"keman_virtual_key": "kmn_" + "abcd1234_" + strings.Repeat("Z", 40),
	}
	for rule, secret := range cases {
		got := Line(`export X="` + secret + `"`)
		if len(got) != 1 || got[0].Rule != rule {
			t.Fatalf("%s: %+v", rule, got)
		}
		if strings.Contains(got[0].Redacted, secret[len(secret)-12:len(secret)-4]) {
			t.Fatalf("%s: redaction keeps the middle: %s", rule, got[0].Redacted)
		}
	}
	vk := Line("kmn_" + "abcd1234_" + strings.Repeat("Z", 40))
	if vk[0].KeyID != "abcd1234" {
		t.Fatalf("virtual key id %+v", vk[0])
	}
}

func TestRulesTakeHostAndEnvFromPreset(t *testing.T) {
	got := Line(fake("gs"+"k_", 52))
	if len(got) != 1 || got[0].Preset != "groq" || got[0].Profile != "openai" || got[0].Host != "api.groq.com" || got[0].Env != "GROQ_API_KEY" {
		t.Fatalf("%+v", got)
	}
	if aws := Line("AK" + "IA" + "ABCDEFGHIJKLMNOP"); aws[0].Preset != "" || aws[0].Profile != "" {
		t.Fatalf("AWS keys cannot be fronted: %+v", aws[0])
	}
}

func TestAnthropicIsNotAlsoOpenAI(t *testing.T) {
	got := Line(fake("sk-ant-"+"api03-", 90) + " " + fake("sk-"+"proj-", 60))
	if len(got) != 2 || got[0].Rule != "anthropic" || got[1].Rule != "openai" {
		t.Fatalf("%+v", got)
	}
}

func TestPlainTextIsClean(t *testing.T) {
	if got := Line(fake("sk_"+"live_", 30) + " // " + AllowMarker); len(got) != 0 {
		t.Fatalf("allow marker ignored: %+v", got)
	}
	for _, s := range []string{"sk-short", "task-management-ticket", "OPENAI_API_KEY=", "kmn_[redacted]"} {
		if got := Line(s); len(got) != 0 {
			t.Fatalf("%q: %+v", s, got)
		}
	}
}

func TestPathsSkipsDependenciesAndBinaries(t *testing.T) {
	dir := t.TempDir()
	secret := fake("sk_"+"live_", 30)
	write := func(rel, body string) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(".env", "A=1\nSTRIPE="+secret+"\n")
	write("node_modules/x/.env", "STRIPE="+secret+"\n")
	write("bin/blob", "\x00\x01"+secret)
	got, err := Paths(context.Background(), []string{dir}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Line != 2 || filepath.Base(got[0].Path) != ".env" {
		t.Fatalf("%+v", got)
	}
}

func TestHistoryFindsDeletedSecrets(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	run := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid", "GIT_CONFIG_GLOBAL=/dev/null")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	secret := fake("gh"+"p_", 36)
	if err := os.WriteFile(filepath.Join(dir, "config.yml"), []byte("name: x\ntoken: "+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run("add", ".")
	run("commit", "-qm", "add config")
	if err := os.WriteFile(filepath.Join(dir, "config.yml"), []byte("name: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run("commit", "-qam", "remove token")
	got, err := History(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Path != "config.yml" || got[0].Line != 2 || len(got[0].Commit) != 40 {
		t.Fatalf("%+v", got)
	}
	if groups := Distinct(append(got, got...)); len(groups) != 1 || len(groups[0].Places) != 2 {
		t.Fatalf("distinct %+v", groups)
	}
}
