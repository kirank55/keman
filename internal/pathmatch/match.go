// Package pathmatch matches "METHOD /pattern" allowlist entries.
// "*" is one path segment. "**" is the rest of the path and only allowed
// as the final segment.
package pathmatch

import (
	"fmt"
	"strings"
	"unicode"
)

type Rule struct {
	Method  string
	Pattern string
}

// ParseLine reads "POST /v1/charges" or "GET /v1/customers/*".
func ParseLine(line string) (Rule, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return Rule{}, fmt.Errorf("empty allowlist entry")
	}
	method, pattern, ok := strings.Cut(line, " ")
	if !ok || method == "" || pattern == "" {
		return Rule{}, fmt.Errorf("allowlist entry %q must be METHOD PATH", line)
	}
	if !strings.HasPrefix(pattern, "/") {
		return Rule{}, fmt.Errorf("path %q must start with /", pattern)
	}
	// One entry is one line: no whitespace or control characters, which
	// also keeps ParseList and ParseLine in agreement.
	if strings.IndexFunc(method+pattern, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return Rule{}, fmt.Errorf("allowlist entry %q must be METHOD PATH on one line", line)
	}
	segs := split(pattern)
	for i, s := range segs {
		if s == "**" && i != len(segs)-1 {
			return Rule{}, fmt.Errorf("** in %q must be the last segment", pattern)
		}
		if strings.Contains(s, "*") && s != "*" && s != "**" {
			return Rule{}, fmt.Errorf("bad wildcard in %q", pattern)
		}
	}
	return Rule{Method: strings.ToUpper(method), Pattern: cleanPattern(pattern)}, nil
}

// ParseList parses newline-separated entries. Blank lines are skipped.
func ParseList(s string) ([]Rule, error) {
	var out []Rule
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		r, err := ParseLine(line)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func (r Rule) String() string { return r.Method + " " + r.Pattern }

// Match returns the operation ("METHOD pattern") of the first matching rule.
func Match(rules []Rule, method, p string) (string, bool) {
	method = strings.ToUpper(method)
	p = normalize(p)
	for _, r := range rules {
		if r.Method != "*" && r.Method != method {
			continue
		}
		if matchPath(r.Pattern, p) {
			return r.String(), true
		}
	}
	return "", false
}

func matchPath(pattern, p string) bool {
	return matchSegs(split(pattern), split(p))
}

func matchSegs(pat, segs []string) bool {
	for i, s := range pat {
		if s == "**" {
			return i == len(pat)-1
		}
		if i >= len(segs) {
			return false
		}
		if s == "*" {
			if segs[i] == "" {
				return false
			}
			continue
		}
		if s != segs[i] {
			return false
		}
	}
	return len(pat) == len(segs)
}

func split(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

func normalize(p string) string {
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if len(p) > 1 {
		p = strings.TrimRight(p, "/")
	}
	return p
}

func cleanPattern(p string) string {
	return normalize(p)
}
