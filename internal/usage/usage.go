// Package usage reads only the fields the proxy is allowed to read:
// model, stream, max_tokens, and stream_options on the way in;
// usage tokens on the way out.
package usage

import (
	"bytes"
	"encoding/json"
)

// Meta is the slice of a request body the proxy acts on.
type Meta struct {
	HasModel  bool
	Model     string
	Stream    bool
	MaxTokens *int64
}

// Result is token usage from a response. InputIncludesCached is true for
// OpenAI, where prompt_tokens already includes cached tokens.
type Result struct {
	Saw                 bool
	Input               int64
	Output              int64
	Cached              int64
	CacheWrite          int64
	InputIncludesCached bool
}

func (d usageDTO) present() bool {
	return d.PromptTokens != nil || d.CompletionTokens != nil || d.InputTokens != nil || d.OutputTokens != nil || d.CacheRead != nil || d.CacheCreation != nil || d.CacheCreationDetail != nil
}

type usageDTO struct {
	PromptTokens        *int64 `json:"prompt_tokens"`
	CompletionTokens    *int64 `json:"completion_tokens"`
	InputTokens         *int64 `json:"input_tokens"`
	OutputTokens        *int64 `json:"output_tokens"`
	CacheRead           *int64 `json:"cache_read_input_tokens"`
	CacheCreation       *int64 `json:"cache_creation_input_tokens"`
	CacheCreationDetail *struct {
		Ephemeral5m *int64 `json:"ephemeral_5m_input_tokens"`
		Ephemeral1h *int64 `json:"ephemeral_1h_input_tokens"`
	} `json:"cache_creation"`
	PromptDetails *struct {
		CachedTokens *int64 `json:"cached_tokens"`
	} `json:"prompt_tokens_details"`
	InputDetails *struct {
		CachedTokens *int64 `json:"cached_tokens"`
	} `json:"input_tokens_details"`
}

// Prepare reads the LLM fields and, for OpenAI streams, sets
// stream_options.include_usage when the client did not set it.
// A body that is not a JSON object is returned unchanged.
func Prepare(profile string, inject bool, body []byte) ([]byte, Meta) {
	var meta Meta
	if len(bytes.TrimSpace(body)) == 0 {
		return body, meta
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil || raw == nil {
		return body, meta
	}
	if m, ok := raw["model"]; ok {
		var s string
		if json.Unmarshal(m, &s) == nil {
			meta.HasModel = true
			meta.Model = s
		}
	}
	if v, ok := raw["stream"]; ok {
		var b bool
		if json.Unmarshal(v, &b) == nil {
			meta.Stream = b
		}
	}
	meta.MaxTokens = firstInt(raw, "max_tokens", "max_completion_tokens")

	if !inject || profile != "openai" || !meta.Stream {
		return body, meta
	}
	so := map[string]json.RawMessage{}
	if existing, ok := raw["stream_options"]; ok && string(existing) != "null" {
		_ = json.Unmarshal(existing, &so)
	}
	if _, set := so["include_usage"]; set {
		return body, meta
	}
	so["include_usage"] = json.RawMessage("true")
	encoded, err := json.Marshal(so)
	if err != nil {
		return body, meta
	}
	raw["stream_options"] = encoded
	out, err := json.Marshal(raw)
	if err != nil {
		return body, meta
	}
	return out, meta
}

func firstInt(raw map[string]json.RawMessage, keys ...string) *int64 {
	for _, k := range keys {
		v, ok := raw[k]
		if !ok || string(v) == "null" {
			continue
		}
		var n int64
		if json.Unmarshal(v, &n) == nil {
			return &n
		}
	}
	return nil
}

// Scanner extracts usage objects from a response without keeping the body.
type Scanner struct {
	profile string
	sse     bool

	// JSON key scanner.
	inString     bool
	escape       bool
	recording    bool
	key          []byte
	pending      bool
	phase        int // 1 want colon, 2 want value, 3 capturing object
	capDepth     int
	capString    bool
	capEscape    bool
	cap          []byte
	merged       usageDTO
	saw          bool
	line         []byte
	sseDecided   bool
	contentIsSSE bool
}

func NewScanner(profile, contentType string) *Scanner {
	s := &Scanner{profile: profile}
	if bytes.Contains([]byte(contentType), []byte("text/event-stream")) {
		s.contentIsSSE = true
		s.sseDecided = true
	}
	return s
}

func (s *Scanner) Feed(p []byte) {
	if s.contentIsSSE || s.sse {
		s.feedSSE(p)
		return
	}
	if !s.sseDecided {
		s.sniff(p)
		return
	}
	s.feedJSON(p)
}

func (s *Scanner) sniff(p []byte) {
	s.line = append(s.line, p...)
	trim := bytes.TrimLeft(s.line, " \t\r\n")
	if len(trim) == 0 {
		return
	}
	buf := s.line
	s.line = nil
	s.sseDecided = true
	if bytes.HasPrefix(trim, []byte("data:")) {
		s.sse = true
		s.feedSSE(buf)
		return
	}
	s.feedJSON(buf)
}

func (s *Scanner) feedSSE(p []byte) {
	s.line = append(s.line, p...)
	for {
		i := bytes.IndexByte(s.line, '\n')
		if i < 0 {
			if len(s.line) > 1<<20 {
				s.line = s.line[:0]
			}
			return
		}
		line := s.line[:i]
		s.line = s.line[i+1:]
		line = bytes.TrimSpace(line)
		if !bytes.HasPrefix(line, []byte("data:")) {
			continue
		}
		payload := bytes.TrimSpace(line[len("data:"):])
		if bytes.Equal(payload, []byte("[DONE]")) || len(payload) == 0 {
			continue
		}
		s.absorb(payload)
	}
}

func (s *Scanner) feedJSON(p []byte) {
	for _, b := range p {
		s.step(b)
	}
}

func (s *Scanner) step(b byte) {
	if s.phase == 3 {
		s.capture(b)
		return
	}
	if s.inString {
		if s.escape {
			s.escape = false
			if s.recording && len(s.key) < 64 {
				s.key = append(s.key, b)
			}
			return
		}
		if b == '\\' {
			s.escape = true
			if s.recording && len(s.key) < 64 {
				s.key = append(s.key, b)
			}
			return
		}
		if b == '"' {
			s.inString = false
			if s.recording {
				s.recording = false
				if bytes.Equal(s.key, []byte("usage")) {
					s.pending = true
					s.phase = 1
				}
				s.key = s.key[:0]
			}
			return
		}
		if s.recording && len(s.key) < 64 {
			s.key = append(s.key, b)
		}
		return
	}
	if s.phase == 1 {
		if b == ' ' || b == '\t' || b == '\n' || b == '\r' {
			return
		}
		if b == ':' {
			s.phase = 2
			return
		}
		s.phase = 0
		s.pending = false
	}
	if s.phase == 2 {
		if b == ' ' || b == '\t' || b == '\n' || b == '\r' {
			return
		}
		s.pending = false
		if b == '{' {
			s.phase = 3
			s.capDepth = 1
			s.cap = append(s.cap[:0], '{')
			return
		}
		s.phase = 0
		// The value is not an object. Fall through so a quote still starts a string.
	}
	if b == '"' {
		s.inString = true
		s.recording = true
		s.key = s.key[:0]
	}
}

func (s *Scanner) capture(b byte) {
	if len(s.cap) < 1<<16 {
		s.cap = append(s.cap, b)
	}
	if s.capString {
		if s.capEscape {
			s.capEscape = false
			return
		}
		if b == '\\' {
			s.capEscape = true
			return
		}
		if b == '"' {
			s.capString = false
		}
		return
	}
	switch b {
	case '"':
		s.capString = true
	case '{':
		s.capDepth++
	case '}':
		s.capDepth--
		if s.capDepth == 0 {
			s.absorb(s.cap)
			s.cap = s.cap[:0]
			s.phase = 0
		}
	}
}

func (s *Scanner) absorb(raw []byte) {
	var dto usageDTO
	if json.Unmarshal(raw, &dto) != nil {
		return
	}
	if !dto.present() {
		// SSE payloads are a full chunk. Pull a nested usage object.
		var wrap struct {
			Usage   *usageDTO `json:"usage"`
			Message *struct {
				Usage *usageDTO `json:"usage"`
			} `json:"message"`
		}
		if json.Unmarshal(raw, &wrap) != nil {
			return
		}
		if wrap.Usage != nil {
			dto = *wrap.Usage
		} else if wrap.Message != nil && wrap.Message.Usage != nil {
			dto = *wrap.Message.Usage
		}
		if !dto.present() {
			return
		}
	}
	s.saw = true
	if dto.PromptTokens != nil {
		s.merged.PromptTokens = dto.PromptTokens
	}
	if dto.CompletionTokens != nil {
		s.merged.CompletionTokens = dto.CompletionTokens
	}
	if dto.InputTokens != nil {
		s.merged.InputTokens = dto.InputTokens
	}
	if dto.OutputTokens != nil {
		s.merged.OutputTokens = dto.OutputTokens
	}
	if dto.CacheRead != nil {
		s.merged.CacheRead = dto.CacheRead
	}
	if dto.CacheCreation != nil {
		s.merged.CacheCreation = dto.CacheCreation
	}
	if dto.CacheCreationDetail != nil {
		s.merged.CacheCreationDetail = dto.CacheCreationDetail
	}
	if dto.PromptDetails != nil && dto.PromptDetails.CachedTokens != nil {
		s.merged.PromptDetails = dto.PromptDetails
	}
	if dto.InputDetails != nil && dto.InputDetails.CachedTokens != nil {
		s.merged.InputDetails = dto.InputDetails
	}
}

// Finish returns whatever usage was seen. Call it when the body ends.
func (s *Scanner) Finish() Result {
	if (s.sse || s.contentIsSSE) && len(bytes.TrimSpace(s.line)) > 0 {
		s.feedSSE([]byte("\n"))
	}
	if !s.contentIsSSE && !s.sse && len(s.line) > 0 {
		s.feedJSON(s.line)
		s.line = nil
	}
	var r Result
	if !s.saw {
		return r
	}
	r.Saw = true
	d := s.merged
	if s.profile == "anthropic" {
		if d.InputTokens != nil {
			r.Input = *d.InputTokens
		}
		if d.OutputTokens != nil {
			r.Output = *d.OutputTokens
		}
		if d.CacheRead != nil {
			r.Cached = *d.CacheRead
		}
		if d.CacheCreation != nil {
			r.CacheWrite = *d.CacheCreation
		} else if d.CacheCreationDetail != nil {
			if d.CacheCreationDetail.Ephemeral5m != nil {
				r.CacheWrite += *d.CacheCreationDetail.Ephemeral5m
			}
			if d.CacheCreationDetail.Ephemeral1h != nil {
				r.CacheWrite += *d.CacheCreationDetail.Ephemeral1h
			}
		}
		r.InputIncludesCached = false
		return r
	}
	r.InputIncludesCached = true
	if d.PromptTokens != nil {
		r.Input = *d.PromptTokens
		if d.CompletionTokens != nil {
			r.Output = *d.CompletionTokens
		}
		if d.PromptDetails != nil && d.PromptDetails.CachedTokens != nil {
			r.Cached = *d.PromptDetails.CachedTokens
		}
		return r
	}
	if d.InputTokens != nil {
		r.Input = *d.InputTokens
	}
	if d.OutputTokens != nil {
		r.Output = *d.OutputTokens
	}
	if d.InputDetails != nil && d.InputDetails.CachedTokens != nil {
		r.Cached = *d.InputDetails.CachedTokens
	}
	return r
}
