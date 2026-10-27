// Package headers strips hop-by-hop, forwarding, and client auth headers
// before a request is sent upstream.
package headers

import "net/http"

// hopByHop are headers that must not be forwarded, plus the forwarding
// headers Keman refuses to pass on or invent.
var forbidden = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
	"Authorization",
	"X-Api-Key",
	"X-Forwarded-For",
	"X-Forwarded-Host",
	"X-Forwarded-Proto",
	"X-Forwarded-Server",
	"X-Real-Ip",
	"Forwarded",
	"Accept-Encoding",
}

// Sanitize copies h without hop-by-hop, forwarding, and auth headers.
// Names listed in Connection are removed as well.
func Sanitize(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, v := range h {
		out[k] = append([]string(nil), v...)
	}
	var extra []string
	for _, c := range out.Values("Connection") {
		for _, name := range splitComma(c) {
			if name != "" {
				extra = append(extra, http.CanonicalHeaderKey(name))
			}
		}
	}
	for _, name := range forbidden {
		out.Del(name)
	}
	for _, name := range extra {
		out.Del(name)
	}
	return out
}

// ApplyTemplate sets "Name: value with {key} replaced".
func ApplyTemplate(h http.Header, template, secret string) error {
	name, value, ok := splitTemplate(template)
	if !ok {
		return errBadTemplate
	}
	h.Set(name, replaceKey(value, secret))
	return nil
}

func TemplateHeaderName(template string) string {
	name, _, ok := splitTemplate(template)
	if !ok {
		return ""
	}
	return http.CanonicalHeaderKey(name)
}

type badTemplate struct{}

func (badTemplate) Error() string { return "auth header template must look like \"Name: value {key}\"" }

var errBadTemplate error = badTemplate{}

func splitTemplate(template string) (string, string, bool) {
	name, value, ok := cut(template, ":")
	if !ok {
		return "", "", false
	}
	name = trim(name)
	value = trim(value)
	if name == "" || value == "" || !containsKey(value) {
		return "", "", false
	}
	return name, value, true
}

func containsKey(v string) bool {
	return len(v) >= 5 && (indexOf(v, "{key}") >= 0)
}

func replaceKey(v, secret string) string {
	return replaceAll(v, "{key}", secret)
}

func splitComma(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			out = append(out, trim(s[start:i]))
			start = i + 1
		}
	}
	return out
}

func cut(s, sep string) (string, string, bool) {
	for i := 0; i+len(sep) <= len(s); i++ {
		if s[i:i+len(sep)] == sep {
			return s[:i], s[i+len(sep):], true
		}
	}
	return "", "", false
}

func trim(s string) string {
	i := 0
	j := len(s)
	for i < j && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	for j > i && (s[j-1] == ' ' || s[j-1] == '\t') {
		j--
	}
	return s[i:j]
}

func indexOf(s, sub string) int {
	if sub == "" {
		return 0
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func replaceAll(s, old, new string) string {
	if old == "" {
		return s
	}
	var b []byte
	for {
		i := indexOf(s, old)
		if i < 0 {
			break
		}
		b = append(b, s[:i]...)
		b = append(b, new...)
		s = s[i+len(old):]
	}
	b = append(b, s...)
	return string(b)
}
