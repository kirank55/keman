package usage

import "testing"

func TestPrepareInjectsIncludeUsage(t *testing.T) {
	body, meta := Prepare("openai", true, []byte(`{"model":"gpt-4o-mini","stream":true}`))
	if !meta.Stream || meta.Model != "gpt-4o-mini" {
		t.Fatalf("%+v", meta)
	}
	if !contains(body, `"include_usage":true`) {
		t.Fatalf("%s", body)
	}
	body, _ = Prepare("openai", true, []byte(`{"model":"gpt-4o-mini","stream":true,"stream_options":{"include_usage":false}}`))
	if contains(body, `"include_usage":true`) {
		t.Fatalf("overwrote explicit false: %s", body)
	}
}

func TestAnthropicNestedCacheCreation(t *testing.T) {
	s := NewScanner("anthropic", "application/json")
	s.Feed([]byte(`{"usage":{"input_tokens":10,"output_tokens":2,"cache_creation":{"ephemeral_5m_input_tokens":80,"ephemeral_1h_input_tokens":20}}}`))
	r := s.Finish()
	if !r.Saw || r.Input != 10 || r.Output != 2 || r.CacheWrite != 100 {
		t.Fatalf("%+v", r)
	}
}

func contains(b []byte, sub string) bool {
	return len(b) >= len(sub) && (string(b) == sub || len(sub) == 0 || indexOf(string(b), sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
