// Package model is the shared vocabulary of stored records and events.
package model

import "time"

const (
	KindStandard = "standard"
	KindCanary   = "canary"

	StatusActive   = "active"
	StatusDisabled = "disabled"
	StatusRevoked  = "revoked"

	ModeAlertOnly   = "alert_only"
	ModeDryRun      = "dry_run"
	ModeAutoDisable = "auto_disable"

	AuthHeader = "header"
	AuthBasic  = "basic"

	ProtocolHTTP = "http"
)

type Upstream struct {
	ID                 string    `json:"id"`
	Name               string    `json:"name"`
	Protocol           string    `json:"protocol"`
	Profile            string    `json:"profile"`
	Preset             string    `json:"preset,omitempty"`
	Host               string    `json:"host"`
	Port               int       `json:"port"`
	TLS                bool      `json:"tls"`
	InsecureSkipVerify bool      `json:"insecure_skip_verify"`
	ServerName         string    `json:"server_name,omitempty"`
	PathAllowlist      []string  `json:"path_allowlist,omitempty"`
	InjectUsage        bool      `json:"inject_usage"`
	CreatedAt          time.Time `json:"created_at"`
}

type Credential struct {
	ID               string    `json:"id"`
	UpstreamID       string    `json:"upstream_id"`
	Name             string    `json:"name"`
	AuthStyle        string    `json:"auth_style"`
	HeaderTemplate   string    `json:"header_template,omitempty"`
	BasicUsername    string    `json:"basic_username,omitempty"`
	SecretIsUserPass bool      `json:"secret_is_userpass,omitempty"`
	Ciphertext       []byte    `json:"-"`
	Nonce            []byte    `json:"-"`
	KeyVersion       int       `json:"key_version"`
	Last4            string    `json:"last4"`
	Plaintext        string    `json:"-"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type VirtualKey struct {
	ID            string     `json:"id"`
	CredentialID  string     `json:"credential_id"`
	Name          string     `json:"name,omitempty"`
	SecretHash    []byte     `json:"-"`
	Kind          string     `json:"kind"`
	Status        string     `json:"status"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	PausedUntil   *time.Time `json:"paused_until,omitempty"`
	DryRunArmed   bool       `json:"dry_run_armed"`
	DryRunBlocked int        `json:"dry_run_blocked"`
	CreatedAt     time.Time  `json:"created_at"`
}

type Policy struct {
	KeyID            string    `json:"virtual_key_id"`
	Mode             string    `json:"mode"`
	RPM              *int      `json:"rpm,omitempty"`
	DailyCapMicro    *int64    `json:"daily_cap_microusd,omitempty"`
	MonthlyCapMicro  *int64    `json:"monthly_cap_microusd,omitempty"`
	PathAllowlist    []string  `json:"paths,omitempty"`
	ModelAllowlist   []string  `json:"models,omitempty"`
	CIDRAllowlist    []string  `json:"cidrs,omitempty"`
	CountryAllowlist []string  `json:"countries,omitempty"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type SpendRow struct {
	KeyID  string
	Period string
	Micro  int64
}

type Event struct {
	ID               int64
	Time             time.Time
	KeyID            string
	Kind             string
	IP               string
	Country          string
	ASN              int
	Operation        string
	Status           int
	LatencyMS        int64
	ReqBytes         int64
	RespBytes        int64
	TokensIn         int64
	TokensOut        int64
	CachedTokens     int64
	CacheWriteTokens int64
	CostMicro        *int64
	CostEstimated    bool
	Model            string
	BlockedCode      string
	Profile          string
	Mode             string
	PausedUntil      time.Time
}

type Detection struct {
	ID       int64          `json:"id"`
	Time     time.Time      `json:"time"`
	KeyID    string         `json:"virtual_key_id"`
	Rule     string         `json:"rule"`
	Severity string         `json:"severity"`
	Evidence map[string]any `json:"evidence"`
	Incident string         `json:"incident,omitempty"`
}

type Incident struct {
	ID        int64
	KeyID     string
	Rule      string
	OpenedAt  time.Time
	LastFired time.Time
	ClosedAt  *time.Time
}

type Baseline struct {
	KeyID         string
	FirstSeen     time.Time
	RequestCount  int
	Countries     map[string]time.Time
	ASNs          map[int]time.Time
	DryRunArmed   bool
	DryRunBlocked int
}

type AlertDestination struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	URL       string    `json:"url"`
	Secret    string    `json:"secret,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type AuditEntry struct {
	ID     int64     `json:"id"`
	Time   time.Time `json:"time"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Target string    `json:"target"`
	Before string    `json:"before"`
	After  string    `json:"after"`
	IP     string    `json:"ip"`
}

type Alert struct {
	Rule     string         `json:"rule"`
	Severity string         `json:"severity"`
	KeyID    string         `json:"virtual_key_id"`
	KeyName  string         `json:"virtual_key_name,omitempty"`
	Kind     string         `json:"kind,omitempty"`
	Summary  string         `json:"summary"`
	Evidence map[string]any `json:"evidence"`
	Baseline map[string]any `json:"baseline"`
	Observed map[string]any `json:"observed"`
	Actions  []AlertAction  `json:"actions"`
	Commands []string       `json:"commands"`
	FiredAt  time.Time      `json:"fired_at"`
}

// AlertAction is one response an operator can take, most decisive first.
// Command is empty when the step happens outside Keman.
type AlertAction struct {
	When    string `json:"when"`
	Command string `json:"command,omitempty"`
}
