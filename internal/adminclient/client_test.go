package adminclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAPIErrorKeepsRawBody(t *testing.T) {
	body := `{"error":{"type":"keman_error","code":"confirm_required","message":"Switching to auto_disable needs confirmation. Review the dry-run report."},"dry_run":{"would_disable":true}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer kma_test" {
			t.Errorf("auth %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	c := New(srv.URL, "kma_test")
	err := c.Call(context.Background(), http.MethodPut, "/v1/keys/k/policy", map[string]any{"mode": "auto_disable"}, nil)
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("got %T %v", err, err)
	}
	if apiErr.Code != "confirm_required" {
		t.Fatal(apiErr.Code)
	}
	if apiErr.Error() != strings.TrimSpace(body) {
		t.Fatal(apiErr.Error())
	}
	if !strings.Contains(apiErr.Message, "confirmation") {
		t.Fatal(apiErr.Message)
	}
}
