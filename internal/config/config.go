// Package config loads server settings from YAML and environment variables.
// Upstreams, credentials, virtual keys, and policies are not in this file.
package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/kirank55/keman/internal/money"
)

type Config struct {
	ProxyListen           string        `yaml:"proxy_listen"`
	AdminListen           string        `yaml:"admin_listen"`
	Database              string        `yaml:"database"`
	TrustedProxies        []string      `yaml:"trusted_proxies"`
	GeoIPCountryDB        string        `yaml:"geoip_country_db"`
	GeoIPASNDB            string        `yaml:"geoip_asn_db"`
	PricesFile            string        `yaml:"prices_file"`
	DefaultReservation    int64         `yaml:"default_reservation_microusd"`
	EventQueueSize        int           `yaml:"event_queue_size"`
	EventRetention        time.Duration `yaml:"event_retention"`
	DetectionRetention    time.Duration `yaml:"detection_retention"`
	SpendFlushInterval    time.Duration `yaml:"spend_flush_interval"`
	SpendFailClosedAfter  time.Duration `yaml:"spend_fail_closed_after"`
	MaxRequestBodyBytes   int64         `yaml:"max_request_body_bytes"`
	MaxHeaderBytes        int           `yaml:"max_header_bytes"`
	ReadHeaderTimeout     time.Duration `yaml:"read_header_timeout"`
	UpstreamDialTimeout   time.Duration `yaml:"upstream_dial_timeout"`
	UpstreamHeaderTimeout time.Duration `yaml:"upstream_response_header_timeout"`
	InvalidKeyRPM         int           `yaml:"invalid_key_rpm"`
	MasterKeyFile         string        `yaml:"master_key_file"`
}

func Defaults() Config {
	return Config{
		ProxyListen:           "0.0.0.0:8080",
		AdminListen:           "127.0.0.1:8081",
		Database:              "keman.db",
		DefaultReservation:    money.Dollar / 10,
		EventQueueSize:        10_000,
		EventRetention:        14 * 24 * time.Hour,
		DetectionRetention:    90 * 24 * time.Hour,
		SpendFlushInterval:    5 * time.Second,
		SpendFailClosedAfter:  60 * time.Second,
		MaxRequestBodyBytes:   32 << 20,
		MaxHeaderBytes:        1 << 16,
		ReadHeaderTimeout:     10 * time.Second,
		UpstreamDialTimeout:   10 * time.Second,
		UpstreamHeaderTimeout: 60 * time.Second,
		InvalidKeyRPM:         60,
	}
}

// Load reads path when it exists, then applies environment overrides.
// A missing file is not an error: defaults and the environment are enough for init.
func Load(path string, getenv func(string) string) (Config, error) {
	cfg := Defaults()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			return Config{}, err
		}
		if err == nil {
			if err := yaml.Unmarshal(b, &cfg); err != nil {
				return Config{}, fmt.Errorf("config: %w", err)
			}
		}
	}
	if cfg.ProxyListen == "" {
		cfg.ProxyListen = Defaults().ProxyListen
	}
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	if v := getenv("KEMAN_PROXY_LISTEN"); v != "" {
		cfg.ProxyListen = v
	}
	if v := getenv("KEMAN_ADMIN_LISTEN"); v != "" {
		cfg.AdminListen = v
	}
	if v := getenv("KEMAN_DATABASE"); v != "" {
		cfg.Database = v
	}
	if v := getenv("KEMAN_TRUSTED_PROXIES"); v != "" {
		cfg.TrustedProxies = splitComma(v)
	}
	if v := getenv("KEMAN_GEOIP_COUNTRY_DB"); v != "" {
		cfg.GeoIPCountryDB = v
	}
	if v := getenv("KEMAN_GEOIP_ASN_DB"); v != "" {
		cfg.GeoIPASNDB = v
	}
	if v := getenv("KEMAN_PRICES_FILE"); v != "" {
		cfg.PricesFile = v
	}
	if v := getenv("KEMAN_MASTER_KEY_FILE"); v != "" {
		cfg.MasterKeyFile = v
	}
	if cfg.EventQueueSize <= 0 {
		cfg.EventQueueSize = Defaults().EventQueueSize
	}
	if cfg.DefaultReservation <= 0 {
		cfg.DefaultReservation = Defaults().DefaultReservation
	}
	if cfg.InvalidKeyRPM <= 0 {
		cfg.InvalidKeyRPM = Defaults().InvalidKeyRPM
	}
	return cfg, nil
}

// UnmarshalYAML accepts duration strings such as "5s" and "336h".
// Fields that the file omits keep whatever value was already set.
func (c *Config) UnmarshalYAML(node *yaml.Node) error {
	var raw map[string]any
	if err := node.Decode(&raw); err != nil {
		return err
	}
	setString := func(key string, dest *string) {
		if v, ok := raw[key].(string); ok && v != "" {
			*dest = v
		}
	}
	setString("proxy_listen", &c.ProxyListen)
	setString("admin_listen", &c.AdminListen)
	setString("database", &c.Database)
	setString("geoip_country_db", &c.GeoIPCountryDB)
	setString("geoip_asn_db", &c.GeoIPASNDB)
	setString("prices_file", &c.PricesFile)
	setString("master_key_file", &c.MasterKeyFile)
	if v, ok := raw["trusted_proxies"]; ok {
		switch t := v.(type) {
		case []any:
			var out []string
			for _, item := range t {
				if s, ok := item.(string); ok && s != "" {
					out = append(out, s)
				}
			}
			c.TrustedProxies = out
		case string:
			c.TrustedProxies = splitComma(t)
		}
	}
	var err error
	if c.EventRetention, err = pickDuration(raw, "event_retention", c.EventRetention); err != nil {
		return err
	}
	if c.DetectionRetention, err = pickDuration(raw, "detection_retention", c.DetectionRetention); err != nil {
		return err
	}
	if c.SpendFlushInterval, err = pickDuration(raw, "spend_flush_interval", c.SpendFlushInterval); err != nil {
		return err
	}
	if c.SpendFailClosedAfter, err = pickDuration(raw, "spend_fail_closed_after", c.SpendFailClosedAfter); err != nil {
		return err
	}
	if c.ReadHeaderTimeout, err = pickDuration(raw, "read_header_timeout", c.ReadHeaderTimeout); err != nil {
		return err
	}
	if c.UpstreamDialTimeout, err = pickDuration(raw, "upstream_dial_timeout", c.UpstreamDialTimeout); err != nil {
		return err
	}
	if c.UpstreamHeaderTimeout, err = pickDuration(raw, "upstream_response_header_timeout", c.UpstreamHeaderTimeout); err != nil {
		return err
	}
	if c.DefaultReservation, err = pickInt64(raw, "default_reservation_microusd", c.DefaultReservation); err != nil {
		return err
	}
	if c.MaxRequestBodyBytes, err = pickInt64(raw, "max_request_body_bytes", c.MaxRequestBodyBytes); err != nil {
		return err
	}
	q, err := pickInt64(raw, "event_queue_size", int64(c.EventQueueSize))
	if err != nil {
		return err
	}
	c.EventQueueSize = int(q)
	h, err := pickInt64(raw, "max_header_bytes", int64(c.MaxHeaderBytes))
	if err != nil {
		return err
	}
	c.MaxHeaderBytes = int(h)
	rpm, err := pickInt64(raw, "invalid_key_rpm", int64(c.InvalidKeyRPM))
	if err != nil {
		return err
	}
	c.InvalidKeyRPM = int(rpm)
	return nil
}

func pickDuration(raw map[string]any, key string, cur time.Duration) (time.Duration, error) {
	v, ok := raw[key]
	if !ok || v == nil {
		return cur, nil
	}
	switch t := v.(type) {
	case string:
		d, err := time.ParseDuration(t)
		if err != nil {
			return 0, fmt.Errorf("config %s: %w", key, err)
		}
		return d, nil
	case int:
		return time.Duration(t), nil
	case int64:
		return time.Duration(t), nil
	case uint64:
		return time.Duration(t), nil
	case float64:
		return time.Duration(int64(t)), nil
	default:
		return 0, fmt.Errorf("config %s: unsupported type %T", key, v)
	}
}

func pickInt64(raw map[string]any, key string, cur int64) (int64, error) {
	v, ok := raw[key]
	if !ok || v == nil {
		return cur, nil
	}
	switch t := v.(type) {
	case int:
		return int64(t), nil
	case int64:
		return t, nil
	case uint64:
		return int64(t), nil
	case float64:
		return int64(t), nil
	case string:
		var n int64
		_, err := fmt.Sscan(t, &n)
		if err != nil {
			return 0, fmt.Errorf("config %s: %w", key, err)
		}
		return n, nil
	default:
		return 0, fmt.Errorf("config %s: unsupported type %T", key, v)
	}
}

func splitComma(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// WriteDefault creates a config file of Defaults() if it does not already exist.
func WriteDefault(path string) error {
	return WriteIfAbsent(path, Defaults())
}

// WriteIfAbsent writes cfg when path does not exist. The file records the
// effective settings (including environment overrides) so serve can reuse it.
func WriteIfAbsent(path string, cfg Config) error {
	if path == "" {
		return nil
	}
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	b, err := Encode(cfg)
	if err != nil {
		return err
	}
	return writePrivate(path, b)
}

// SetMasterKeyFile records keyFile in the config at path.
// A missing file is created from the defaults.
func SetMasterKeyFile(path, keyFile string) error {
	keyFile = strings.TrimSpace(keyFile)
	if keyFile == "" {
		return fmt.Errorf("master key file path is empty")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		cfg := Defaults()
		cfg.MasterKeyFile = keyFile
		return WriteIfAbsent(path, cfg)
	}
	scalar, err := yamlScalar(keyFile)
	if err != nil {
		return err
	}
	line := "master_key_file: " + scalar
	nl := "\n"
	text := string(b)
	if strings.Contains(text, "\r\n") {
		nl = "\r\n"
	}
	parts := strings.Split(text, nl)
	replaced := false
	for i, ln := range parts {
		if !replaced && strings.HasPrefix(strings.TrimSpace(ln), "master_key_file:") {
			parts[i] = line
			replaced = true
		}
	}
	if !replaced {
		if len(parts) > 0 && parts[len(parts)-1] == "" {
			parts = append(parts[:len(parts)-1], line, "")
		} else {
			parts = append(parts, line)
		}
	}
	out := strings.Join(parts, nl)
	if !strings.HasSuffix(out, nl) {
		out += nl
	}
	return writePrivate(path, []byte(out))
}

func yamlScalar(s string) (string, error) {
	b, err := yaml.Marshal(s)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func writePrivate(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// Encode renders a readable YAML config.
func Encode(cfg Config) ([]byte, error) {
	if cfg.ProxyListen == "" {
		cfg.ProxyListen = Defaults().ProxyListen
	}
	if cfg.AdminListen == "" {
		cfg.AdminListen = Defaults().AdminListen
	}
	if cfg.Database == "" {
		cfg.Database = Defaults().Database
	}
	var b strings.Builder
	b.WriteString("# Keman server settings. Keys and policies live in the database.\n")
	fmt.Fprintf(&b, "proxy_listen: %s\n", cfg.ProxyListen)
	fmt.Fprintf(&b, "admin_listen: %s\n", cfg.AdminListen)
	fmt.Fprintf(&b, "database: %s\n", quote(cfg.Database))
	if len(cfg.TrustedProxies) == 0 {
		b.WriteString("trusted_proxies: []\n")
	} else {
		b.WriteString("trusted_proxies:\n")
		for _, p := range cfg.TrustedProxies {
			fmt.Fprintf(&b, "  - %s\n", p)
		}
	}
	if cfg.GeoIPCountryDB != "" {
		fmt.Fprintf(&b, "geoip_country_db: %s\n", quote(cfg.GeoIPCountryDB))
	}
	if cfg.GeoIPASNDB != "" {
		fmt.Fprintf(&b, "geoip_asn_db: %s\n", quote(cfg.GeoIPASNDB))
	}
	if cfg.PricesFile != "" {
		fmt.Fprintf(&b, "prices_file: %s\n", quote(cfg.PricesFile))
	}
	if cfg.MasterKeyFile != "" {
		fmt.Fprintf(&b, "master_key_file: %s\n", quote(cfg.MasterKeyFile))
	}
	fmt.Fprintf(&b, "default_reservation_microusd: %d\n", cfg.DefaultReservation)
	fmt.Fprintf(&b, "event_queue_size: %d\n", cfg.EventQueueSize)
	fmt.Fprintf(&b, "event_retention: %s\n", formatDuration(cfg.EventRetention))
	fmt.Fprintf(&b, "detection_retention: %s\n", formatDuration(cfg.DetectionRetention))
	fmt.Fprintf(&b, "spend_flush_interval: %s\n", formatDuration(cfg.SpendFlushInterval))
	fmt.Fprintf(&b, "spend_fail_closed_after: %s\n", formatDuration(cfg.SpendFailClosedAfter))
	fmt.Fprintf(&b, "max_request_body_bytes: %d\n", cfg.MaxRequestBodyBytes)
	fmt.Fprintf(&b, "max_header_bytes: %d\n", cfg.MaxHeaderBytes)
	fmt.Fprintf(&b, "read_header_timeout: %s\n", formatDuration(cfg.ReadHeaderTimeout))
	fmt.Fprintf(&b, "upstream_dial_timeout: %s\n", formatDuration(cfg.UpstreamDialTimeout))
	fmt.Fprintf(&b, "upstream_response_header_timeout: %s\n", formatDuration(cfg.UpstreamHeaderTimeout))
	fmt.Fprintf(&b, "invalid_key_rpm: %d\n", cfg.InvalidKeyRPM)
	return []byte(b.String()), nil
}

// quote renders s as a YAML scalar, quoting it only when needed.
func quote(s string) string {
	q, err := yamlScalar(s)
	if err != nil {
		return strconv.Quote(s)
	}
	return q
}

func formatDuration(d time.Duration) string {
	if d == 0 {
		return "0s"
	}
	if d%time.Hour == 0 {
		return strconv.FormatInt(int64(d/time.Hour), 10) + "h"
	}
	if d%time.Minute == 0 {
		return strconv.FormatInt(int64(d/time.Minute), 10) + "m"
	}
	if d%time.Second == 0 {
		return strconv.FormatInt(int64(d/time.Second), 10) + "s"
	}
	return d.String()
}

// AdminURL is the HTTP URL the CLI should use for cfg.AdminListen.
// 0.0.0.0 and :: are rewritten to 127.0.0.1 so the client can connect.
func AdminURL(cfg Config) string {
	addr := cfg.AdminListen
	if addr == "" {
		addr = Defaults().AdminListen
	}
	if strings.HasPrefix(addr, "unix://") {
		return addr
	}
	if strings.HasPrefix(addr, "/") {
		return "unix://" + addr
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "http://127.0.0.1:8081"
	}
	if host == "0.0.0.0" || host == "::" || host == "[::]" || host == "" {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port)
}

// AdminIsLocal is true when the admin listener is loopback or a Unix socket.
func AdminIsLocal(cfg Config) bool {
	addr := cfg.AdminListen
	if addr == "" {
		return true
	}
	if strings.HasPrefix(addr, "unix://") || strings.HasPrefix(addr, "/") {
		return true
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
