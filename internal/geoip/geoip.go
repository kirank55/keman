// Package geoip looks up country and ASN. The database is not bundled.
package geoip

import (
	"fmt"
	"net"

	"github.com/oschwald/maxminddb-golang"
)

// Resolver maps an IP to a country code and an ASN. Missing data is empty.
type Resolver interface {
	Lookup(ip net.IP) (country string, asn int)
	HasCountry() bool
}

// Map is a test resolver.
type Map struct {
	Country   map[string]string
	ASN       map[string]int
	CountryDB bool
}

func (m Map) Lookup(ip net.IP) (string, int) {
	if ip == nil {
		return "", 0
	}
	return m.Country[ip.String()], m.ASN[ip.String()]
}

func (m Map) HasCountry() bool { return m.CountryDB || len(m.Country) > 0 }

// DB reads MaxMind GeoLite2-style country and ASN databases.
type DB struct {
	country *maxminddb.Reader
	asn     *maxminddb.Reader
}

func Open(countryPath, asnPath string) (*DB, error) {
	d := &DB{}
	if countryPath != "" {
		r, err := maxminddb.Open(countryPath)
		if err != nil {
			return nil, fmt.Errorf("country database: %w", err)
		}
		d.country = r
	}
	if asnPath != "" {
		r, err := maxminddb.Open(asnPath)
		if err != nil {
			_ = d.Close()
			return nil, fmt.Errorf("asn database: %w", err)
		}
		d.asn = r
	}
	return d, nil
}

func (d *DB) HasCountry() bool { return d != nil && d.country != nil }

func (d *DB) Close() error {
	if d == nil {
		return nil
	}
	var err error
	if d.country != nil {
		err = d.country.Close()
	}
	if d.asn != nil {
		if e := d.asn.Close(); err == nil {
			err = e
		}
	}
	return err
}

func (d *DB) Lookup(ip net.IP) (string, int) {
	if d == nil || ip == nil {
		return "", 0
	}
	var country string
	if d.country != nil {
		var rec struct {
			Country struct {
				ISOCode string `maxminddb:"iso_code"`
			} `maxminddb:"country"`
			CountryCode string `maxminddb:"country_code"`
		}
		if err := d.country.Lookup(ip, &rec); err == nil {
			country = rec.Country.ISOCode
			if country == "" {
				country = rec.CountryCode
			}
		}
	}
	var asn int
	if d.asn != nil {
		var rec struct {
			Number uint `maxminddb:"autonomous_system_number"`
		}
		if err := d.asn.Lookup(ip, &rec); err == nil {
			asn = int(rec.Number)
		}
	}
	return country, asn
}
