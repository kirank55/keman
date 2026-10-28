package pathmatch

import "testing"

func TestMatchRejectsAmbiguousPaths(t *testing.T) {
	rules, err := ParseList("GET /v1/files/**\nGET /v1/customers/*")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{
		"/v1/files/../charges",
		"/v1/files/./x",
		"/v1/customers/..",
		"/v1/files/..;/charges",
		"/v1/files/a\\..\\charges",
		"/v1/files/a\x00",
	} {
		if op, ok := Match(rules, "GET", p); ok {
			t.Errorf("%q matched %q", p, op)
		}
	}
	for _, p := range []string{"/v1/files/file-abc/content", "/v1/customers/cus_1", "/v1/files/a.b", "/v1/files/..x"} {
		if _, ok := Match(rules, "GET", p); !ok {
			t.Errorf("%q should match", p)
		}
	}
}
