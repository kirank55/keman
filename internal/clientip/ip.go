// Package clientip decides the single client address used everywhere.
package clientip

import (
	"net"
	"strings"
)

// FromRequest returns the client IP.
// An untrusted peer is the client, and its X-Forwarded-For is ignored.
// A trusted peer yields the rightmost X-Forwarded-For entry that is not
// itself a trusted proxy. If every entry is trusted, the leftmost entry
// is used. If the header is empty or unparseable, the peer is used.
func FromRequest(remoteAddr, xff string, trusted []*net.IPNet) net.IP {
	peer := parseHost(remoteAddr)
	if peer == nil {
		return nil
	}
	if !contains(trusted, peer) {
		return peer
	}
	var parsed []net.IP
	for _, part := range strings.Split(xff, ",") {
		ip := parseHost(strings.TrimSpace(part))
		if ip != nil {
			parsed = append(parsed, ip)
		}
	}
	for i := len(parsed) - 1; i >= 0; i-- {
		if !contains(trusted, parsed[i]) {
			return parsed[i]
		}
	}
	if len(parsed) > 0 {
		return parsed[0]
	}
	return peer
}

func parseHost(s string) net.IP {
	if s == "" {
		return nil
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip
	}
	host, _, err := net.SplitHostPort(s)
	if err != nil {
		host = s
	}
	host = strings.Trim(host, "[]")
	return net.ParseIP(host)
}

func contains(nets []*net.IPNet, ip net.IP) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ParseCIDRs parses a list of CIDR strings.
func ParseCIDRs(in []string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !strings.Contains(s, "/") {
			if ip := net.ParseIP(s); ip != nil {
				if ip.To4() != nil {
					s += "/32"
				} else {
					s += "/128"
				}
			}
		}
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}
