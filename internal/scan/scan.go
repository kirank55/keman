// Package scan finds real provider keys, and Keman virtual keys, in files and
// git history, so they can be moved behind Keman before they leak further.
package scan

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Rule is one secret format.
type Rule struct {
	ID       string
	Provider string
	// Profile is the Keman profile that can front this key. Empty means
	// Keman cannot proxy it, and the advice is to rotate it at the provider.
	Profile string
	Host    string
	Env     string
	re      *regexp.Regexp
}

// Rules are checked in order; the first match at a position wins, so the
// more specific prefixes come first.
var Rules = []Rule{
	{ID: "keman_virtual_key", Provider: "Keman virtual key", re: regexp.MustCompile(`\bkmn_([0-9A-Za-z]{8})_[0-9A-Za-z]{20,}`)},
	{ID: "anthropic", Provider: "Anthropic", Profile: "anthropic", Host: "api.anthropic.com", Env: "ANTHROPIC_API_KEY", re: regexp.MustCompile(`\bsk-ant-(?:api|admin)\d\d-[A-Za-z0-9_-]{20,}`)},
	{ID: "openrouter", Provider: "OpenRouter", Profile: "openai", Host: "openrouter.ai", Env: "OPENROUTER_API_KEY", re: regexp.MustCompile(`\bsk-or-v1-[0-9a-f]{64}\b`)},
	{ID: "openai", Provider: "OpenAI", Profile: "openai", Host: "api.openai.com", Env: "OPENAI_API_KEY", re: regexp.MustCompile(`\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}|\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}`)},
	{ID: "stripe", Provider: "Stripe", Profile: "generic", Host: "api.stripe.com", Env: "STRIPE_SECRET_KEY", re: regexp.MustCompile(`\b(?:sk|rk)_live_[0-9A-Za-z]{24,}`)},
	{ID: "github", Provider: "GitHub", Profile: "generic", Host: "api.github.com", Env: "GITHUB_TOKEN", re: regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}|\bgithub_pat_[A-Za-z0-9_]{60,}`)},
	{ID: "slack", Provider: "Slack", Profile: "generic", Host: "slack.com", Env: "SLACK_TOKEN", re: regexp.MustCompile(`\bxox[abposr]-[0-9A-Za-z-]{20,}`)},
	{ID: "google_api", Provider: "Google API", Profile: "", Env: "GOOGLE_API_KEY", re: regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
	{ID: "aws_access_key", Provider: "AWS access key", Profile: "", Env: "AWS_ACCESS_KEY_ID", re: regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
}

// Finding is one secret in one place. Secret is never set to the full value.
type Finding struct {
	Rule     string `json:"rule"`
	Provider string `json:"provider"`
	Path     string `json:"path"`
	Line     int    `json:"line"`
	Commit   string `json:"commit,omitempty"`
	Redacted string `json:"redacted"`
	// KeyID is set for Keman virtual keys: the id part, which is safe to show.
	KeyID   string `json:"virtual_key_id,omitempty"`
	Profile string `json:"profile,omitempty"`
	Host    string `json:"host,omitempty"`
	Env     string `json:"env,omitempty"`
	// fingerprint groups the same secret across places without keeping it.
	fingerprint string
}

// Options controls what is skipped.
type Options struct {
	MaxFileBytes int64
}

const defaultMaxFileBytes = 2 << 20

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, ".venv": true, "venv": true,
	"__pycache__": true, ".terraform": true, "dist": true, "build": true, "target": true,
}

// AllowMarker on a line skips it, for test fixtures that only look like keys.
const AllowMarker = "keman:allow"

// Line returns the findings in one line of text.
func Line(text string) []Finding {
	if strings.Contains(text, AllowMarker) {
		return nil
	}
	type hit struct {
		at int
		f  Finding
	}
	var hits []hit
	var taken [][2]int
	for _, r := range Rules {
		for _, loc := range r.re.FindAllStringSubmatchIndex(text, -1) {
			start, end := loc[0], loc[1]
			if overlaps(taken, start, end) {
				continue
			}
			taken = append(taken, [2]int{start, end})
			secret := text[start:end]
			f := Finding{
				Rule: r.ID, Provider: r.Provider, Redacted: Redact(secret),
				Profile: r.Profile, Host: r.Host, Env: r.Env, fingerprint: secret,
			}
			if r.ID == "keman_virtual_key" && len(loc) >= 4 && loc[2] >= 0 {
				f.KeyID = text[loc[2]:loc[3]]
			}
			hits = append(hits, hit{at: start, f: f})
		}
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].at < hits[j].at })
	out := make([]Finding, len(hits))
	for i, h := range hits {
		out[i] = h.f
	}
	return out
}

func overlaps(taken [][2]int, start, end int) bool {
	for _, t := range taken {
		if start < t[1] && t[0] < end {
			return true
		}
	}
	return false
}

// Redact keeps a recognizable prefix and the last four characters.
func Redact(secret string) string {
	keep := 6
	if i := strings.LastIndexAny(secret[:min(len(secret), 16)], "-_"); i >= 0 && i+1 < 14 {
		keep = i + 1
	}
	if len(secret) <= keep+4 {
		return strings.Repeat("*", len(secret))
	}
	return secret[:keep] + "…" + secret[len(secret)-4:]
}

// Reader scans r line by line and labels findings with path.
func Reader(r io.Reader, path string) ([]Finding, error) {
	var out []Finding
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	n := 0
	for sc.Scan() {
		n++
		for _, f := range Line(sc.Text()) {
			f.Path = path
			f.Line = n
			out = append(out, f)
		}
	}
	return out, sc.Err()
}

// Paths walks each root and scans text files. Directories that hold
// dependencies or build output, and binary or oversized files, are skipped.
func Paths(ctx context.Context, roots []string, opt Options) ([]Finding, error) {
	limit := opt.MaxFileBytes
	if limit <= 0 {
		limit = defaultMaxFileBytes
	}
	var out []Finding
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if d.IsDir() {
				if path != root && skipDirs[d.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			info, err := d.Info()
			if err != nil || info.Size() > limit {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil || binary(b) {
				return nil
			}
			found, err := Reader(bytes.NewReader(b), path)
			if err != nil {
				return nil
			}
			out = append(out, found...)
			return nil
		})
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

func binary(b []byte) bool {
	head := b
	if len(head) > 8000 {
		head = head[:8000]
	}
	return bytes.IndexByte(head, 0) >= 0
}

// History scans every line ever added in the git repository at dir, on all
// refs. A secret deleted in a later commit is still in history, and still
// leaked to anyone who cloned the repository.
func History(ctx context.Context, dir string) ([]Finding, error) {
	cmd := exec.CommandContext(ctx, "git", "-C", dir, "log", "--all", "-p", "--no-color", "--no-ext-diff", "--unified=0", "--format=commit %H")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	out := parseLog(stdout)
	if err := cmd.Wait(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return out, &GitError{Msg: msg}
	}
	return out, nil
}

// GitError is a failed git command.
type GitError struct{ Msg string }

func (e *GitError) Error() string { return "git: " + e.Msg }

func parseLog(r io.Reader) []Finding {
	var out []Finding
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	var commit, path string
	line := 0
	for sc.Scan() {
		t := sc.Text()
		switch {
		case strings.HasPrefix(t, "commit "):
			commit = strings.TrimPrefix(t, "commit ")
			path = ""
		case strings.HasPrefix(t, "+++ "):
			path = strings.TrimPrefix(strings.TrimPrefix(t, "+++ "), "b/")
		case strings.HasPrefix(t, "@@ "):
			line = hunkStart(t)
		case strings.HasPrefix(t, "+") && path != "":
			for _, f := range Line(t[1:]) {
				f.Path = path
				f.Line = line
				f.Commit = commit
				out = append(out, f)
			}
			line++
		}
	}
	return out
}

// hunkStart reads the new-file line number from "@@ -a,b +c,d @@".
func hunkStart(h string) int {
	i := strings.Index(h, " +")
	if i < 0 {
		return 0
	}
	rest := h[i+2:]
	n := 0
	for _, c := range rest {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// Group is every place one secret appears.
type Group struct {
	First  Finding
	Places []Finding
}

// Distinct groups findings by secret, in the order each was first seen.
func Distinct(found []Finding) []Group {
	idx := map[string]int{}
	var out []Group
	for _, f := range found {
		if i, ok := idx[f.fingerprint]; ok {
			out[i].Places = append(out[i].Places, f)
			continue
		}
		idx[f.fingerprint] = len(out)
		out = append(out, Group{First: f, Places: []Finding{f}})
	}
	return out
}
