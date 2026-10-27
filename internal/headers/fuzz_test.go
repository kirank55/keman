package headers

import (
	"net/http"
	"strings"
	"testing"
)

func FuzzSanitize(f *testing.F) {
	f.Add("Authorization", "Bearer secret", "X-Forwarded-For", "1.2.3.4", "Connection", "close, X-Trace", "X-Trace", "1")
	f.Add("Accept", "application/json", "Forwarded", "for=1.1.1.1", "X-Api-Key", "abc", "Accept-Encoding", "gzip")
	f.Fuzz(func(t *testing.T, k1, v1, k2, v2, k3, v3, k4, v4 string) {
		h := make(http.Header)
		if k1 != "" {
			h.Add(k1, v1)
		}
		if k2 != "" {
			h.Add(k2, v2)
		}
		if k3 != "" {
			h.Add(k3, v3)
		}
		if k4 != "" {
			h.Add(k4, v4)
		}
		out := Sanitize(h)
		for name := range out {
			switch http.CanonicalHeaderKey(name) {
			case "Authorization", "X-Api-Key", "X-Forwarded-For", "X-Forwarded-Host", "Forwarded", "Accept-Encoding", "Connection":
				t.Fatalf("header %s survived", name)
			}
		}
		if strings.Contains(strings.ToLower(out.Get("Authorization")), "bearer") && h.Get("Authorization") != "" {
			t.Fatal("authorization forwarded")
		}
		_ = ApplyTemplate(http.Header{}, "Authorization: Bearer {key}", "s3cret")
	})
}
