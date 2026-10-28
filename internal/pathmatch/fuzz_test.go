package pathmatch

import "testing"

func FuzzMatch(f *testing.F) {
	f.Add("POST /v1/chat/completions", "POST", "/v1/chat/completions")
	f.Add("GET /v1/models/*", "GET", "/v1/models/gpt-4o")
	f.Add("POST /v1/responses/**", "POST", "/v1/responses/abc/cancel")
	f.Add("GET /**/nope", "GET", "/a/nope")
	f.Add("POST /v1/*", "GET", "/v1/x")
	f.Fuzz(func(t *testing.T, line, method, path string) {
		rule, err := ParseLine(line)
		if err != nil {
			return
		}
		op, ok := Match([]Rule{rule}, method, path)
		if ok && op == "" {
			t.Fatal("match without an operation")
		}
		if ok && len(op) > 4096 {
			t.Fatal("operation unexpectedly huge")
		}
		rules, err := ParseList(line + "\n" + line)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = Match(rules, method, path)
	})
}
