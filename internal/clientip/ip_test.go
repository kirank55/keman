package clientip

import "testing"

func TestUntrustedPeerIgnoresForwardedFor(t *testing.T) {
	ip := FromRequest("198.51.100.8:443", "203.0.113.5", nil)
	if ip.String() != "198.51.100.8" {
		t.Fatal(ip)
	}
}

func TestTrustedPeerUsesRightmostUntrusted(t *testing.T) {
	nets, err := ParseCIDRs([]string{"10.0.0.0/8", "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	ip := FromRequest("10.1.1.1:1234", "203.0.113.5, 10.9.9.9, 192.0.2.1", nets)
	if ip.String() != "203.0.113.5" {
		t.Fatal(ip)
	}
	ip = FromRequest("10.1.1.1:1234", "10.2.2.2, 10.3.3.3", nets)
	if ip.String() != "10.2.2.2" {
		t.Fatal(ip)
	}
	ip = FromRequest("10.1.1.1:1234", "", nets)
	if ip.String() != "10.1.1.1" {
		t.Fatal(ip)
	}
}
