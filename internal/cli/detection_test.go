package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/kirank55/keman/internal/detect"
)

func TestDetectionTestSuite(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"detection", "test"}, nil, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code %d\n%s\n%s", code, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr %s", stderr.String())
	}
	text := stdout.String()
	for _, want := range []string{
		"detection test",
		"stolen-key",
		"rate_spike medium",
		"new_country medium",
		"auto_disable would disable the key",
		"dry_run would have disabled the key",
		"1 later request would have been blocked",
		"learning",
		"  ok",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q\n%s", want, text)
		}
	}
	if !strings.Contains(text, strconv.Itoa(len(detect.CheckNames()))+" passed") {
		t.Fatalf("summary\n%s", text)
	}

	stdout.Reset()
	code = Run(context.Background(), []string{"detection", "test", "--scenario", "stolen-key"}, nil, nil, &stdout, &stderr)
	if code != 0 || strings.Contains(stdout.String(), "spend_spike") || !strings.Contains(stdout.String(), "1 passed") {
		t.Fatalf("scenario %d\n%s\n%s", code, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = Run(context.Background(), []string{"detection", "test", "--json"}, nil, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("json %d %s", code, stderr.String())
	}
	var suite detect.Suite
	if err := json.Unmarshal(stdout.Bytes(), &suite); err != nil {
		t.Fatal(err)
	}
	if !suite.OK || suite.Failed != 0 || suite.Passed != len(detect.CheckNames()) {
		t.Fatalf("%+v", suite)
	}

	stdout.Reset()
	stderr.Reset()
	code = Run(context.Background(), []string{"detection", "test", "--list"}, nil, nil, &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "stolen-key\n") || strings.Contains(stdout.String(), "passed") {
		t.Fatalf("list %d\n%s\n%s", code, stdout.String(), stderr.String())
	}

	stderr.Reset()
	code = Run(context.Background(), []string{"detection", "test", "--scenario", "nope"}, nil, nil, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "unknown scenario") {
		t.Fatalf("unknown %d %s", code, stderr.String())
	}
}

func TestDetectionTestFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	body := `{"time":"2026-10-28T12:00:00Z","key_id":"k","country":"US","asn":64500,"status":200,"cost_micro":5000001,"mode":"auto_disable"}` + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"detection", "test", "--file", path, "--expect", "spend_spike"}, nil, nil, &stdout, &stderr)
	if code != 1 || !strings.Contains(stdout.String(), "missing spend_spike") {
		t.Fatalf("cold %d\n%s\n%s", code, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = Run(context.Background(), []string{"detection", "test", "--file", path, "--learned", "--expect", "spend_spike"}, nil, nil, &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "spend_spike high") || !strings.Contains(stdout.String(), "hour=$5.000001") || strings.Contains(stdout.String(), "model=") {
		t.Fatalf("warm %d\n%s\n%s", code, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = Run(context.Background(), []string{"detection", "test", "--file", path, "--learned", "--expect", "spend_spike", "--expect-disable"}, nil, nil, &stdout, &stderr)
	if code != 1 || !strings.Contains(stdout.String(), "missing auto_disable") {
		t.Fatalf("disable %d\n%s\n%s", code, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = Run(context.Background(), []string{"detection", "test", "--file", path, "--learned", "--json"}, nil, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("file json %d %s", code, stderr.String())
	}
	var out struct {
		OK    bool `json:"ok"`
		Fired []struct {
			Rule  string `json:"rule"`
			Alert bool   `json:"alert"`
		} `json:"fired"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if !out.OK || len(out.Fired) != 1 || out.Fired[0].Rule != "spend_spike" || !out.Fired[0].Alert {
		t.Fatalf("%+v", out)
	}

	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	code = Run(context.Background(), []string{"detection", "test", "--file", bad}, nil, nil, &stdout, &stderr)
	if code != 1 || stderr.Len() == 0 {
		t.Fatalf("bad json %d %s", code, stderr.String())
	}

	empty := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(empty, []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	code = Run(context.Background(), []string{"detection", "test", "--file", empty}, nil, nil, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "no events") {
		t.Fatalf("empty %d %s", code, stderr.String())
	}
}

func TestDetectionTestStdin(t *testing.T) {
	line := `{"time":"2026-10-28T12:00:00Z","blocked_code":"path_not_allowed","status":403,"mode":"alert_only"}` + "\n"
	var body strings.Builder
	for i := 0; i < 5; i++ {
		body.WriteString(line)
	}
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"detection", "test", "--file", "-", "--expect", "allowlist_violations"}, nil, strings.NewReader(body.String()), &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "allowlist_violations medium") {
		t.Fatalf("%d\n%s\n%s", code, stdout.String(), stderr.String())
	}
}

func TestProxyBaseRewritesWildcard(t *testing.T) {
	got, err := proxyBase("0.0.0.0:8080")
	if err != nil || got != "http://127.0.0.1:8080" {
		t.Fatalf("%s %v", got, err)
	}
	got, err = proxyBase("127.0.0.1:9090")
	if err != nil || got != "http://127.0.0.1:9090" {
		t.Fatalf("%s %v", got, err)
	}
	if _, err := proxyBase("not a listen"); err == nil {
		t.Fatal("expected error")
	}
}

func TestDetectionUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"detection"}, nil, nil, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "detection test") {
		t.Fatalf("%d %s", code, stderr.String())
	}
	stderr.Reset()
	code = Run(context.Background(), []string{"detection", "test", "--learned"}, nil, nil, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "--file") {
		t.Fatalf("%d %s", code, stderr.String())
	}
	stderr.Reset()
	code = Run(context.Background(), []string{"detection", "test", "--live"}, nil, nil, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "secret-file") {
		t.Fatalf("live %d %s", code, stderr.String())
	}
	stdout.Reset()
	code = Run(context.Background(), []string{"help"}, nil, nil, &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "detection test") {
		t.Fatalf("help missing detection test\n%s", stdout.String())
	}
}
