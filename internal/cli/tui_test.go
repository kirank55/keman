package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestTUIRejectsPipe(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), nil, func(k string) string {
		if k == "KEMAN_ADMIN_TOKEN" {
			return "kma_test"
		}
		return ""
	}, strings.NewReader(""), &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code %d\n%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "terminal") {
		t.Fatal(stderr.String())
	}
}

func TestTUIMissingTokenStillNeedsTerminal(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), nil, func(string) string { return "" }, strings.NewReader(""), &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code %d\n%s", code, stderr.String())
	}
	if strings.Contains(stderr.String(), "set --admin-token") || !strings.Contains(stderr.String(), "terminal") {
		t.Fatal(stderr.String())
	}
}

func TestTUIHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"--help"}, func(string) string { return "" }, nil, &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "KEMAN_ADMIN_TOKEN") || strings.Contains(stdout.String(), "tui") {
		t.Fatalf("code %d\n%s\n%s", code, stdout.String(), stderr.String())
	}
}

func TestTUIIsNotACommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"tui"}, func(string) string { return "" }, strings.NewReader(""), &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), `unknown command "tui"`) {
		t.Fatalf("code %d\n%s\n%s", code, stdout.String(), stderr.String())
	}
}
