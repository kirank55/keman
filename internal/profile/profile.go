// Package profile holds the built-in path allowlists for LLM profiles.
package profile

import "github.com/kirank55/keman/internal/pathmatch"

const (
	OpenAI    = "openai"
	Anthropic = "anthropic"
	Generic   = "generic"
)

func IsLLM(name string) bool {
	return name == OpenAI || name == Anthropic
}

func Valid(name string) bool {
	return name == OpenAI || name == Anthropic || name == Generic
}

// Builtin is the allowlist shipped with an LLM profile.
// A policy can narrow it. Generic upstreams have no built-in list.
func Builtin(name string) []pathmatch.Rule {
	var lines []string
	switch name {
	case OpenAI:
		lines = []string{
			"POST /v1/chat/completions",
			"POST /v1/completions",
			"POST /v1/embeddings",
			"POST /v1/responses",
			"POST /v1/responses/**",
			"GET /v1/responses/**",
			"POST /v1/images/generations",
			"POST /v1/images/edits",
			"POST /v1/images/variations",
			"POST /v1/audio/speech",
			"POST /v1/audio/transcriptions",
			"POST /v1/audio/translations",
			"POST /v1/moderations",
			"GET /v1/models",
			"GET /v1/models/*",
			"POST /v1/files",
			"GET /v1/files",
			"GET /v1/files/*",
			"DELETE /v1/files/*",
			"POST /v1/batches",
			"GET /v1/batches",
			"GET /v1/batches/*",
			"POST /v1/batches/*/cancel",
			"POST /v1/fine_tuning/jobs",
			"GET /v1/fine_tuning/jobs",
			"GET /v1/fine_tuning/jobs/**",
		}
	case Anthropic:
		lines = []string{
			"POST /v1/messages",
			"POST /v1/messages/count_tokens",
			"POST /v1/messages/batches",
			"GET /v1/messages/batches",
			"GET /v1/messages/batches/*",
			"POST /v1/messages/batches/*/cancel",
			"POST /v1/complete",
			"GET /v1/models",
			"GET /v1/models/*",
		}
	default:
		return nil
	}
	var out []pathmatch.Rule
	for _, line := range lines {
		r, err := pathmatch.ParseLine(line)
		if err != nil {
			panic(err)
		}
		out = append(out, r)
	}
	return out
}
