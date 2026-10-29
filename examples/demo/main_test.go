package main

import (
	"net"
	"path/filepath"
	"testing"

	"github.com/kirank55/keman/internal/geoip"
)

func TestGeoIPReadsBack(t *testing.T) {
	dir := t.TempDir()
	if err := writeGeoIP(dir); err != nil {
		t.Fatal(err)
	}
	db, err := geoip.Open(filepath.Join(dir, "country.mmdb"), filepath.Join(dir, "asn.mmdb"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for ip, want := range map[string]struct {
		country string
		asn     int
	}{
		"203.0.113.10":   {"US", 64500},
		"203.0.113.127":  {"US", 64500},
		"203.0.113.200":  {"BR", 64510},
		"198.51.100.7":   {"US", 64501},
		"192.0.2.20":     {"DE", 64502},
		"192.0.2.200":    {"NL", 64511},
		"198.51.100.200": {"SG", 64512},
		"10.0.0.1":       {"", 0},
	} {
		c, a := db.Lookup(net.ParseIP(ip))
		if c != want.country || a != want.asn {
			t.Errorf("%s: got %q %d, want %q %d", ip, c, a, want.country, want.asn)
		}
	}
}
