package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kirank55/keman/internal/config"
	"github.com/kirank55/keman/internal/expiry"
	"github.com/kirank55/keman/internal/preset"
	"github.com/kirank55/keman/internal/scan"
)

// exitFindings is the exit code of scan and exposure --strict when they find
// something, so CI can tell a finding from a usage error (2) or a failure (1).
const exitFindings = 3

func (c *cmd) keyRotate(api *client, args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(c.stderr, "usage: keman key rotate <id-or-name> [--grace 24h]")
		return 2
	}
	f := newFlags(args[1:])
	graceText := f.str("grace")
	if err := f.done(); err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 2
	}
	body := map[string]any{}
	if graceText != "" {
		grace, err := expiry.Span(graceText)
		if err != nil {
			fmt.Fprintln(c.stderr, "--grace: "+err.Error())
			return 2
		}
		body["grace_seconds"] = int64(grace / time.Second)
	}
	id, err := c.resolveKey(api, args[0])
	if err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 1
	}
	var raw json.RawMessage
	if err := api.call(c.ctx, http.MethodPost, "/v1/keys/"+id+"/rotate", body, &raw); err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 1
	}
	var out struct {
		Replaced struct {
			Name      string     `json:"name"`
			Status    string     `json:"status"`
			ExpiresAt *time.Time `json:"expires_at"`
		} `json:"replaced"`
	}
	_ = json.Unmarshal(raw, &out)
	fmt.Fprintln(c.stderr, "store the new virtual key (token) now; it is not shown again")
	switch {
	case out.Replaced.Status == "revoked":
		fmt.Fprintf(c.stderr, "the old key is revoked and renamed %q\n", out.Replaced.Name)
	case out.Replaced.ExpiresAt != nil:
		fmt.Fprintf(c.stderr, "the old key, renamed %q, works until %s; move the app to the new key before then\n",
			out.Replaced.Name, out.Replaced.ExpiresAt.UTC().Format(time.RFC3339))
	}
	var v any
	_ = json.Unmarshal(raw, &v)
	return c.printJSON(v)
}

func (c *cmd) keyExpiry(api *client, args []string) int {
	if len(args) != 2 {
		fmt.Fprintln(c.stderr, "usage: keman key expiry <id-or-name> <30d|2026-12-31|RFC3339|never>")
		return 2
	}
	at, err := expiry.Parse(args[1], time.Now())
	if err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 2
	}
	id, err := c.resolveKey(api, args[0])
	if err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 1
	}
	body := map[string]any{"expires_at": nil}
	if at != nil {
		body["expires_at"] = at.Format(time.RFC3339)
	}
	var out any
	if err := api.call(c.ctx, http.MethodPut, "/v1/keys/"+id+"/expiry", body, &out); err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 1
	}
	return c.printJSON(out)
}

// canary creates a decoy key and prints it as the settings a thief would
// expect to find: an API key variable and a base URL. Only the snippet goes
// to stdout, so it can be redirected straight into the file being planted.
func (c *cmd) canary(args []string) int {
	if len(args) == 0 || args[0] != "create" {
		fmt.Fprintln(c.stderr, "usage: keman canary create --credential NAME --name NAME [--base-url URL] [--prefix VAR] [--format env|json]")
		return 2
	}
	f := newFlags(args[1:])
	credName := f.str("credential")
	name := f.str("name")
	baseURL := strings.TrimRight(f.str("base-url"), "/")
	prefix := strings.ToUpper(f.str("prefix"))
	format := f.str("format")
	if err := f.done(); err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 2
	}
	if name == "" {
		fmt.Fprintln(c.stderr, "canary create requires --name")
		return 2
	}
	if format == "" {
		format = "env"
	}
	if format != "env" && format != "json" {
		fmt.Fprintln(c.stderr, "--format must be env or json")
		return 2
	}
	api, err := c.api()
	if err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 1
	}
	credID, err := c.resolveCredential(api, credName)
	if err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 1
	}
	up, err := c.credentialUpstream(api, credID)
	if err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 1
	}
	if baseURL == "" {
		cfg, err := c.loadConfig()
		if err != nil {
			fmt.Fprintln(c.stderr, err.Error())
			return 1
		}
		baseURL = localProxyURL(cfg)
		fmt.Fprintf(c.stderr, "warning: no --base-url; using %s. The canary only fires if whoever finds it can reach Keman at that URL.\n", baseURL)
	}
	keyVar, urlVar, path := canaryNames(up)
	if prefix != "" {
		keyVar, urlVar = prefix+"_API_KEY", prefix+"_BASE_URL"
	}
	var created struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	body := map[string]any{"credential_id": credID, "name": name, "kind": "canary"}
	if err := api.call(c.ctx, http.MethodPost, "/v1/keys", body, &created); err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 1
	}
	if format == "json" {
		enc := json.NewEncoder(c.stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]string{keyVar: created.Token, urlVar: baseURL + path})
	} else {
		fmt.Fprintf(c.stdout, "%s=%s\n%s=%s\n", keyVar, created.Token, urlVar, baseURL+path)
	}
	fmt.Fprintf(c.stderr, "canary %s (%s) created. Plant the lines above where a thief would look: a .env in a repo,\n", name, created.ID)
	fmt.Fprintln(c.stderr, "CI variables, an old config or a backup. Any use raises a critical alert and never reaches the upstream.")
	fmt.Fprintln(c.stderr, "Keep the snippet free of comments that mention keman or canaries.")
	return 0
}

type upstreamInfo struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Profile string `json:"profile"`
	Preset  string `json:"preset"`
	Host    string `json:"host"`
}

func (c *cmd) credentialUpstream(api *client, credID string) (upstreamInfo, error) {
	var creds []struct {
		ID         string `json:"id"`
		UpstreamID string `json:"upstream_id"`
	}
	if err := api.call(c.ctx, http.MethodGet, "/v1/credentials", nil, &creds); err != nil {
		return upstreamInfo{}, err
	}
	var upID string
	for _, cr := range creds {
		if cr.ID == credID {
			upID = cr.UpstreamID
		}
	}
	var ups []upstreamInfo
	if err := api.call(c.ctx, http.MethodGet, "/v1/upstreams", nil, &ups); err != nil {
		return upstreamInfo{}, err
	}
	for _, u := range ups {
		if u.ID == upID {
			return u, nil
		}
	}
	return upstreamInfo{}, fmt.Errorf("upstream for credential %s not found", credID)
}

// canaryNames picks the variables and base path an SDK for this upstream
// would use, so the decoy looks like ordinary configuration.
func canaryNames(up upstreamInfo) (keyVar, urlVar, path string) {
	if p, ok := preset.Get(up.Preset); ok {
		base := p.Env
		for _, suffix := range []string{"_API_KEY", "_SECRET_KEY", "_SERVER_TOKEN", "_AUTH_TOKEN", "_BOT_TOKEN", "_API_TOKEN", "_TOKEN", "_KEY"} {
			if strings.HasSuffix(base, suffix) {
				base = strings.TrimSuffix(base, suffix)
				break
			}
		}
		return p.Env, base + "_BASE_URL", p.BasePath
	}
	prefix, path := legacyCanaryPrefix(up)
	return prefix + "_API_KEY", prefix + "_BASE_URL", path
}

func legacyCanaryPrefix(up upstreamInfo) (prefix, path string) {
	switch {
	case up.Profile == "anthropic":
		return "ANTHROPIC", ""
	case up.Profile == "openai" && strings.Contains(up.Host, "openrouter"):
		return "OPENROUTER", "/api/v1"
	case up.Profile == "openai":
		return "OPENAI", "/v1"
	}
	var b strings.Builder
	for _, r := range strings.ToUpper(up.Name) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "API", ""
	}
	return b.String(), ""
}

func localProxyURL(cfg config.Config) string {
	host, port, err := net.SplitHostPort(cfg.ProxyListen)
	if err != nil {
		return "http://127.0.0.1:8080"
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port)
}

type exposureKey struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Status   string `json:"status"`
	Exposure *[]struct {
		Code     string `json:"code"`
		Severity string `json:"severity"`
		Message  string `json:"message"`
		Fix      string `json:"fix"`
	} `json:"exposure"`
}

// exposure lists keys that would be easy to abuse if they leaked.
func (c *cmd) exposure(args []string) int {
	f := newFlags(args)
	strict := f.bool("strict")
	if err := f.done(); err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 2
	}
	api, err := c.api()
	if err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 1
	}
	var keys []exposureKey
	if err := api.call(c.ctx, http.MethodGet, "/v1/keys", nil, &keys); err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 1
	}
	live, flagged := 0, 0
	for _, k := range keys {
		if k.Exposure == nil {
			fmt.Fprintln(c.stderr, "the server did not report exposure; is it older than this CLI?")
			return 1
		}
		if k.Status == "active" && k.Kind != "canary" {
			live++
		}
		if len(*k.Exposure) == 0 {
			continue
		}
		flagged++
		label := k.ID
		if k.Name != "" {
			label = k.Name + " (" + k.ID + ")"
		}
		fmt.Fprintln(c.stdout, label)
		for _, x := range *k.Exposure {
			fmt.Fprintf(c.stdout, "  %-7s %s\n", x.Severity, x.Message)
			fmt.Fprintf(c.stdout, "          fix: %s\n", x.Fix)
		}
		fmt.Fprintln(c.stdout)
	}
	if flagged == 0 {
		fmt.Fprintf(c.stdout, "%d active keys checked; none are open to every address, unexpiring, or idle.\n", live)
		return 0
	}
	fmt.Fprintf(c.stdout, "%d of %d active keys would be easy to abuse if they leaked.\n", flagged, live)
	if strict {
		return exitFindings
	}
	return 0
}

// scan looks for real secrets in files, and with --history in git history.
// It needs no server: it is meant for repos and CI.
func (c *cmd) scan(args []string) int {
	f := newFlags(args)
	history := f.bool("history")
	asJSON := f.bool("json")
	roots := f.args
	f.args = nil
	if err := f.done(); err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 2
	}
	if len(roots) == 0 {
		roots = []string{"."}
	}
	for _, r := range roots {
		if _, err := os.Stat(r); err != nil {
			fmt.Fprintln(c.stderr, err.Error())
			return 1
		}
	}
	found, err := scan.Paths(c.ctx, roots, scan.Options{})
	if err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 1
	}
	if history {
		for _, r := range roots {
			past, err := scan.History(c.ctx, r)
			var gitErr *scan.GitError
			if errors.As(err, &gitErr) {
				fmt.Fprintf(c.stderr, "%s: no git history scanned (%s)\n", r, gitErr.Msg)
				continue
			}
			if err != nil {
				fmt.Fprintf(c.stderr, "%s: no git history scanned (%s)\n", r, err.Error())
				continue
			}
			found = append(found, past...)
		}
	}
	groups := scan.Distinct(found)
	if asJSON {
		if found == nil {
			found = []scan.Finding{}
		}
		if code := c.printJSON(found); code != 0 {
			return code
		}
	} else {
		c.printScan(groups, len(found))
	}
	if len(groups) > 0 {
		return exitFindings
	}
	return 0
}

func (c *cmd) printScan(groups []scan.Group, places int) {
	w := c.stdout
	if len(groups) == 0 {
		fmt.Fprintln(w, "no API keys found")
		return
	}
	sort.SliceStable(groups, func(i, j int) bool {
		return groups[i].First.Rule == "keman_virtual_key" && groups[j].First.Rule != "keman_virtual_key"
	})
	fmt.Fprintf(w, "found %s in %s\n", count(len(groups), "secret", "secrets"), count(places, "place", "places"))
	for _, g := range groups {
		f := g.First
		fmt.Fprintf(w, "\n%s  %s\n", f.Provider, f.Redacted)
		inHistory := false
		for _, p := range g.Places {
			if p.Commit != "" {
				inHistory = true
				fmt.Fprintf(w, "  %s:%d  (commit %s)\n", p.Path, p.Line, p.Commit[:min(len(p.Commit), 12)])
			} else {
				fmt.Fprintf(w, "  %s:%d\n", p.Path, p.Line)
			}
		}
		switch {
		case f.Rule == "keman_virtual_key":
			fmt.Fprintln(w, "  A virtual key in plain text. Replace it and revoke this copy:")
			fmt.Fprintf(w, "    keman key rotate %s --grace 0\n", f.KeyID)
		case f.Profile == "":
			fmt.Fprintf(w, "  Keman cannot front %s keys. Rotate it at the provider and keep it in a secret store.\n", f.Provider)
		default:
			name := f.Preset
			switch {
			case f.Rule == "google_api":
				fmt.Fprintln(w, "  If it is a Gemini API key, move it behind Keman so apps only ever hold a virtual key:")
			default:
				fmt.Fprintln(w, "  Move it behind Keman so apps only ever hold a virtual key:")
			}
			fmt.Fprintf(w, "    keman upstream add --preset %s    (once)\n", name)
			fmt.Fprintf(w, "    keman credential add --upstream %s --name %s-main --secret-env %s\n", name, name, f.Env)
			fmt.Fprintf(w, "    keman key create --credential %s-main --name <app> --expires 90d\n", name)
			if inHistory {
				fmt.Fprintf(w, "  It is in git history, so treat it as leaked: rotate it at %s too.\n", f.Provider)
			} else {
				fmt.Fprintf(w, "  Then rotate it at %s: anyone who could read this file could have copied it.\n", f.Provider)
			}
		}
	}
}

func count(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}
