package cli

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/kirank55/keman/internal/detect"
	"github.com/kirank55/keman/internal/model"
	"github.com/kirank55/keman/internal/money"
)

const detectionTestUsage = `usage: keman detection test [--scenario name] [--json]
       keman detection test --list
       keman detection test --file events.jsonl [--learned] [--expect rule,rule] [--expect-disable]
       keman detection test --live --secret-file virtual.key [--proxy URL]`

const liveProbePath = "/v1/detection-test"

func (c *cmd) detection(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.stderr, "usage: keman detection list [--key id]")
		fmt.Fprintln(c.stderr, detectionTestUsage)
		return 2
	}
	switch args[0] {
	case "list":
		return c.detectionList(args[1:])
	case "test":
		return c.detectionTest(args[1:])
	default:
		fmt.Fprintln(c.stderr, "usage: keman detection list [--key id]")
		fmt.Fprintln(c.stderr, detectionTestUsage)
		return 2
	}
}

func (c *cmd) detectionList(args []string) int {
	f := newFlags(args)
	key := f.str("key")
	if err := f.done(); err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 2
	}
	api, err := c.api()
	if err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 1
	}
	path := "/v1/detections"
	if key != "" {
		id, err := c.resolveKey(api, key)
		if err != nil {
			fmt.Fprintln(c.stderr, err.Error())
			return 1
		}
		path += "?key_id=" + url.QueryEscape(id)
	}
	var out any
	if err := api.call(c.ctx, http.MethodGet, path, nil, &out); err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 1
	}
	return c.printJSON(out)
}

func (c *cmd) detectionTest(args []string) int {
	f := newFlags(args)
	scenario := f.str("scenario")
	file := f.str("file")
	learned := f.bool("learned")
	asJSON := f.bool("json")
	list := f.bool("list")
	expectDisable := f.bool("expect-disable")
	live := f.bool("live")
	proxy := f.str("proxy")
	expects, err := splitExpect(f.list("expect"))
	if err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 2
	}
	var secret string
	if live {
		secret, err = c.secret(f)
		if err != nil {
			fmt.Fprintln(c.stderr, err.Error())
			return 2
		}
	}
	if err := f.done(); err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		fmt.Fprintln(c.stderr, detectionTestUsage)
		return 2
	}
	if list {
		if scenario != "" || file != "" || learned || asJSON || expectDisable || live || proxy != "" || len(expects) > 0 {
			fmt.Fprintln(c.stderr, "usage: keman detection test --list")
			return 2
		}
		for _, name := range detect.CheckNames() {
			fmt.Fprintln(c.stdout, name)
		}
		return 0
	}
	if live && (file != "" || scenario != "" || learned || expectDisable || len(expects) > 0) {
		fmt.Fprintln(c.stderr, "--live runs against a proxy; it does not take --file, --scenario, or --expect")
		return 2
	}
	if live {
		return c.detectionLive(secret, proxy, asJSON)
	}
	if proxy != "" {
		fmt.Fprintln(c.stderr, "--proxy applies to --live")
		return 2
	}
	if file != "" && scenario != "" {
		fmt.Fprintln(c.stderr, "use either --file or --scenario")
		return 2
	}
	if file == "" && (learned || expectDisable || len(expects) > 0) {
		fmt.Fprintln(c.stderr, "--learned, --expect, and --expect-disable apply to --file")
		return 2
	}
	if file != "" {
		return c.detectionFile(file, learned, asJSON, expects, expectDisable)
	}
	checks, err := detect.RunChecks(scenario)
	if err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 2
	}
	suite := detect.Summarize(checks)
	if asJSON {
		if c.printJSON(suite) != 0 {
			return 1
		}
		if !suite.OK {
			return 1
		}
		return 0
	}
	writeChecks(c.stdout, checks)
	if !suite.OK {
		return 1
	}
	return 0
}

func (c *cmd) detectionFile(path string, learned, asJSON bool, expects []string, expectDisable bool) int {
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(c.stdin)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 1
	}
	events, err := detect.LoadFixture(data)
	if err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 1
	}
	if len(events) == 0 {
		fmt.Fprintln(c.stderr, "file has no events")
		return 1
	}
	res := detect.ReplayEvents(events, detect.Options{Learned: learned})
	missing := missingExpect(res, expects, expectDisable)
	ok := len(missing) == 0
	if asJSON {
		out := struct {
			OK      bool     `json:"ok"`
			Missing []string `json:"missing,omitempty"`
			detect.Result
		}{OK: ok, Missing: missing, Result: res}
		if c.printJSON(out) != 0 {
			return 1
		}
		if !ok {
			return 1
		}
		return 0
	}
	writeReplay(c.stdout, res)
	if !ok {
		fmt.Fprintf(c.stdout, "missing %s\n", strings.Join(missing, ", "))
		return 1
	}
	return 0
}

// detectionLive sends five requests the path allowlist refuses, then waits
// until the proxy's own detection worker stores allowlist_violations.
func (c *cmd) detectionLive(secret, proxy string, asJSON bool) int {
	if strings.TrimSpace(secret) == "" {
		fmt.Fprintln(c.stderr, "virtual key is empty")
		return 2
	}
	if proxy == "" {
		cfg, err := c.loadConfig()
		if err != nil {
			fmt.Fprintln(c.stderr, err.Error())
			return 1
		}
		proxy, err = proxyBase(cfg.ProxyListen)
		if err != nil {
			fmt.Fprintln(c.stderr, err.Error())
			return 2
		}
	} else if !strings.Contains(proxy, "://") {
		proxy = "http://" + proxy
	}
	proxy = strings.TrimRight(proxy, "/")
	api, err := c.api()
	if err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 1
	}
	before, err := c.detectionRows(api)
	if err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 1
	}
	seen := map[int64]bool{}
	for _, row := range before {
		seen[row.ID] = true
	}
	if err := c.probeBlocked(proxy, secret); err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		if strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "connect:") {
			fmt.Fprintf(c.stderr, "start the proxy with: keman --config %s serve\n", c.g.configPath)
		}
		return 1
	}
	fresh, err := c.waitAllowlist(api, seen)
	if err != nil {
		fmt.Fprintln(c.stderr, err.Error())
		return 1
	}
	if asJSON {
		return c.printJSON(map[string]any{"ok": true, "detections": fresh})
	}
	writeLive(c.stdout, fresh)
	return 0
}

func (c *cmd) probeBlocked(proxy, token string) error {
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	endpoint := proxy + liveProbePath
	for i := 0; i < 5; i++ {
		req, err := http.NewRequestWithContext(c.ctx, http.MethodPost, endpoint, strings.NewReader(`{}`))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("proxy %s: %w", proxy, err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		if resp.Header.Get("X-Keman-Error") != "path_not_allowed" {
			return fmt.Errorf("request %d returned %d %s, want path_not_allowed", i+1, resp.StatusCode, strings.TrimSpace(string(body)))
		}
	}
	return nil
}

func (c *cmd) detectionRows(api *client) ([]model.Detection, error) {
	var rows []model.Detection
	if err := api.call(c.ctx, http.MethodGet, "/v1/detections", nil, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

func (c *cmd) waitAllowlist(api *client, seen map[int64]bool) ([]model.Detection, error) {
	deadline := time.Now().Add(3 * time.Second)
	for {
		rows, err := c.detectionRows(api)
		if err != nil {
			return nil, err
		}
		var fresh []model.Detection
		for _, row := range rows {
			if !seen[row.ID] {
				fresh = append(fresh, row)
			}
		}
		for _, row := range fresh {
			if row.Rule == detect.RuleAllow {
				return fresh, nil
			}
		}
		if !time.Now().Before(deadline) {
			return nil, fmt.Errorf("allowlist_violations was not stored")
		}
		select {
		case <-c.ctx.Done():
			return nil, c.ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func proxyBase(listen string) (string, error) {
	host, port, err := net.SplitHostPort(listen)
	if err != nil || port == "" {
		return "", fmt.Errorf("proxy_listen %q is not host:port", listen)
	}
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port), nil
}

func writeLive(w io.Writer, rows []model.Detection) {
	fmt.Fprintln(w, "detection test")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "live")
	fmt.Fprintln(w, "  5 requests blocked with path_not_allowed")
	for _, row := range rows {
		line := "  " + row.Rule + " " + row.Severity
		if text := evidenceText(row.Evidence); text != "" {
			line += "  " + text
		}
		fmt.Fprintln(w, line)
	}
	fmt.Fprintln(w, "  ok")
}

func splitExpect(vals []string) ([]string, error) {
	var out []string
	for _, v := range vals {
		for _, part := range strings.Split(v, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				return nil, fmt.Errorf("empty --expect rule")
			}
			out = append(out, part)
		}
	}
	return out, nil
}

func missingExpect(res detect.Result, wants []string, disable bool) []string {
	have := map[string]bool{}
	for _, f := range res.Fired {
		have[f.Rule] = true
	}
	var missing []string
	seen := map[string]bool{}
	add := func(name string) {
		if seen[name] {
			return
		}
		seen[name] = true
		missing = append(missing, name)
	}
	for _, w := range wants {
		if !have[w] {
			add(w)
		}
	}
	if disable && !res.AutoDisable {
		add("auto_disable")
	}
	return missing
}

func writeChecks(w io.Writer, checks []detect.Check) {
	fmt.Fprintln(w, "detection test")
	passed := 0
	for _, ch := range checks {
		fmt.Fprintln(w)
		fmt.Fprintln(w, ch.Name)
		for _, a := range ch.Alerts {
			fmt.Fprintf(w, "  %s %s\n", a.Rule, a.Severity)
		}
		if ch.AutoDisable {
			fmt.Fprintln(w, "  auto_disable would disable the key")
		}
		if ch.DryChecked {
			if ch.DryRun {
				fmt.Fprintln(w, "  dry_run would have disabled the key")
			}
			if ch.WouldBlock > 0 {
				fmt.Fprintf(w, "  %s\n", blockedPhrase(ch.WouldBlock))
			}
		}
		if ch.OK {
			fmt.Fprintln(w, "  ok")
			passed++
			continue
		}
		fmt.Fprintf(w, "  %s\n  failed\n", ch.Problem)
	}
	fmt.Fprintln(w)
	failed := len(checks) - passed
	if failed == 0 {
		fmt.Fprintf(w, "%d passed\n", passed)
		return
	}
	fmt.Fprintf(w, "%d passed, %d failed\n", passed, failed)
}

func writeReplay(w io.Writer, res detect.Result) {
	fmt.Fprintf(w, "%d events\n\n", res.Events)
	alerts := 0
	var lines []string
	var commands []string
	seenCmd := map[string]bool{}
	for _, f := range res.Fired {
		if !f.Alert {
			continue
		}
		alerts++
		line := f.Time.UTC().Format(time.RFC3339) + "  " + f.Rule + " " + f.Severity
		if text := evidenceText(f.Evidence); text != "" {
			line += "  " + text
		}
		lines = append(lines, line)
		for _, command := range f.Commands {
			if command == "" || seenCmd[command] {
				continue
			}
			seenCmd[command] = true
			commands = append(commands, command)
		}
	}
	if len(lines) == 0 {
		fmt.Fprintln(w, "no alerts")
	} else {
		for _, line := range lines {
			fmt.Fprintln(w, line)
		}
	}
	fmt.Fprintln(w)
	var tail []string
	if res.AutoDisable && res.AutoDisableAt != nil {
		tail = append(tail, "auto_disable would disable the key at "+res.AutoDisableAt.UTC().Format(time.RFC3339))
	}
	if res.DryRun && res.DryRunAt != nil {
		tail = append(tail, "dry_run would have disabled the key at "+res.DryRunAt.UTC().Format(time.RFC3339))
	}
	if res.WouldBlock > 0 {
		tail = append(tail, blockedPhrase(res.WouldBlock))
	}
	if len(commands) > 0 {
		if len(tail) > 0 {
			tail = append(tail, "")
		}
		tail = append(tail, "responses")
		for _, command := range commands {
			tail = append(tail, "  "+command)
		}
	}
	for _, line := range tail {
		fmt.Fprintln(w, line)
	}
	if len(tail) > 0 {
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "%s, %s\n", countPhrase(len(res.Fired), "detection", "detections"), countPhrase(alerts, "alert", "alerts"))
}

func countPhrase(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

func blockedPhrase(n int) string {
	if n == 1 {
		return "1 later request would have been blocked"
	}
	return fmt.Sprintf("%d later requests would have been blocked", n)
}

func evidenceText(m map[string]any) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		v := m[k]
		if s, ok := v.(string); ok && s == "" {
			continue
		}
		if name, ok := strings.CutSuffix(k, "_microusd"); ok {
			if n, ok := asInt64(v); ok {
				parts = append(parts, name+"=$"+money.FormatUSD(n))
				continue
			}
		}
		parts = append(parts, fmt.Sprintf("%s=%v", k, v))
	}
	return strings.Join(parts, " ")
}

func asInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int64:
		return n, true
	case float64:
		return int64(n), n == float64(int64(n))
	default:
		return 0, false
	}
}
