package tui

import (
	"context"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
)

type screen int

const (
	screenKeys screen = iota
	screenDetections
	screenAudit
	screenSetup
)

type overlay int

const (
	overlayNone overlay = iota
	overlayDetail
	overlayPolicy
	overlayRevoke
	overlayCreate
	overlayUpstream
	overlayCredential
	overlayToken
	overlayConfirm
	overlayHelp
	overlayAdmin
)

// Key is one virtual key as the terminal UI shows it.
type Key struct {
	ID            string
	Name          string
	CredentialID  string
	Kind          string
	Status        string
	ExpiresAt     *time.Time
	DryRunArmed   bool
	DryRunBlocked int
	Policy        *Policy
	SpendToday    int64
	SpendMonth    int64
	SpendOpen     int64
}

// Policy is the editable limit set for a virtual key.
type Policy struct {
	Mode            string
	RPM             *int
	DailyCapMicro   *int64
	MonthlyCapMicro *int64
	Paths           []string
	Models          []string
	CIDRs           []string
	Countries       []string
}

// Detection is one rule firing.
type Detection struct {
	Time     time.Time
	KeyID    string
	Rule     string
	Severity string
}

// AuditRow is one admin action.
type AuditRow struct {
	Time   time.Time
	Actor  string
	Action string
	Target string
}

// Upstream is a configured target, without credentials.
type Upstream struct {
	ID      string
	Name    string
	Profile string
	Host    string
	Port    int
	TLS     bool
}

// Credential is a real key's metadata. The secret is never included.
type Credential struct {
	ID         string
	Name       string
	UpstreamID string
	AuthStyle  string
	Last4      string
}

// UpstreamDraft is a new upstream. Paths replace the profile's built-in list.
type UpstreamDraft struct {
	Name    string
	Profile string
	Host    string
	Port    int
	TLS     bool
	Paths   []string
}

// CredentialDraft carries a new upstream secret only until the admin API accepts it.
type CredentialDraft struct {
	UpstreamID string
	Name       string
	Secret     string
}

// AlertDest is a webhook or Slack destination. The signing secret is never included.
type AlertDest struct {
	ID   string
	Kind string
	URL  string
}

// DryRun is the seven-day auto-disable preview.
type DryRun struct {
	WouldDisable       bool       `json:"would_disable"`
	WouldDisableAt     *time.Time `json:"would_disable_at,omitempty"`
	RequestsWouldBlock int        `json:"requests_would_block"`
	Detections         int        `json:"detections"`
}

// CreatedKey is the one response that contains a virtual key secret.
type CreatedKey struct {
	ID     string
	Name   string
	Token  string
	Kind   string
	Status string
}

// ConfirmError means auto_disable was not saved. Report is the dry run.
type ConfirmError struct {
	Message string
	Report  DryRun
}

func (e *ConfirmError) Error() string {
	if e == nil || e.Message == "" {
		return "confirmation required"
	}
	return e.Message
}

// API is the admin surface the UI needs. Tests substitute a fake.
type API interface {
	ListKeys(ctx context.Context) ([]Key, error)
	ListDetections(ctx context.Context, keyID string) ([]Detection, error)
	ListAudit(ctx context.Context) ([]AuditRow, error)
	ListUpstreams(ctx context.Context) ([]Upstream, error)
	ListCredentials(ctx context.Context) ([]Credential, error)
	ListAlerts(ctx context.Context) ([]AlertDest, error)
	SetStatus(ctx context.Context, id, action string) error
	PutPolicy(ctx context.Context, id string, p Policy, confirm bool) (DryRun, error)
	CreateKey(ctx context.Context, credentialID, name, kind string) (CreatedKey, error)
	AddUpstream(ctx context.Context, d UpstreamDraft) (Upstream, error)
	AddCredential(ctx context.Context, d CredentialDraft) (Credential, error)
	KeyUsage(ctx context.Context, id string) (KeyUsage, error)
}

// KeyUsage is stored request activity for one virtual key.
type KeyUsage struct {
	Requests   int
	TokensIn   int64
	TokensOut  int64
	Cached     int64
	CacheWrite int64
	CostMicro  int64
	Priced     int
	Estimated  int
	LastSeen   time.Time
	Clients    []UsageClient
	Models     []UsageModel
	Recent     []UsageRequest
}

// UsageClient is a source address seen for a key.
type UsageClient struct {
	IP       string
	Country  string
	ASN      int
	Requests int
	LastSeen time.Time
}

// UsageModel is totals for one model name.
type UsageModel struct {
	Model     string
	Requests  int
	TokensIn  int64
	TokensOut int64
	CostMicro int64
	Priced    int
}

// UsageRequest is one proxied call.
type UsageRequest struct {
	Time          time.Time
	IP            string
	Country       string
	ASN           int
	Operation     string
	Status        int
	LatencyMS     int64
	Model         string
	TokensIn      int64
	TokensOut     int64
	CostMicro     *int64
	CostEstimated bool
	BlockedCode   string
}

type model struct {
	ctx  context.Context
	api  API
	base string

	width   int
	height  int
	gen     int
	loading bool

	screen   screen
	overlay  overlay
	helpFrom overlay
	cursor   int
	scroll   int

	keys   []Key
	dets   []Detection
	audits []AuditRow
	ups    []Upstream
	creds  []Credential
	alerts []AlertDest

	filters       [4]string
	loaded        [4]bool
	errFromPoll   bool
	filtering     bool
	filterInput   textinput.Model
	detailID      string
	detailDets    []Detection
	detailUsage   KeyUsage
	detailLoaded  bool
	revokeID      string
	revokeExpect  string
	revokeInput   textinput.Model
	policyID      string
	policyName    string
	policyKeep    Policy
	polMode       int
	polField      int
	policyConfirm bool
	confirmReport DryRun
	rpmInput      textinput.Model
	dailyInput    textinput.Model
	monthlyInput  textinput.Model

	createField int
	createCred  int
	createKind  int
	nameInput   textinput.Model

	upField   int
	upProfile int
	upTLS     bool
	upName    textinput.Model
	upHost    textinput.Model
	upPort    textinput.Model
	upPaths   textinput.Model

	credField  int
	credUp     int
	credMode   int
	credName   textinput.Model
	credEnv    textinput.Model
	credSecret textinput.Model

	adminHeld  bool
	adminInput textinput.Model
	setToken   func(string)

	getenv func(string) string

	token     string
	tokenName string

	errMsg string
	note   string
}

func newModel(ctx context.Context, api API, base string) model {
	if ctx == nil {
		ctx = context.Background()
	}
	m := model{
		ctx:     ctx,
		api:     api,
		base:    base,
		loading: true,
	}
	m.filterInput = bareInput(64, 24, "")
	m.revokeInput = bareInput(64, 32, "")
	m.nameInput = bareInput(64, 24, "laptop")
	m.rpmInput = bareInput(8, 12, "unlimited")
	m.dailyInput = bareInput(16, 12, "no cap")
	m.monthlyInput = bareInput(16, 12, "no cap")
	m.upName = bareInput(64, 24, "openrouter")
	m.upHost = bareInput(128, 36, "openrouter.ai")
	m.upPort = bareInput(5, 6, "443")
	m.upPaths = bareInput(300, 72, "POST /path")
	m.credName = bareInput(64, 24, "primary")
	m.credEnv = bareInput(64, 32, "OPENROUTER_API_KEY")
	m.credSecret = bareInput(512, 32, "key")
	m.credSecret.EchoMode = textinput.EchoPassword
	m.adminInput = bareInput(256, 48, "kma_...")
	m.adminInput.EchoMode = textinput.EchoPassword
	return m
}

func bareInput(limit, width int, placeholder string) textinput.Model {
	in := textinput.New()
	in.Prompt = ""
	in.Placeholder = placeholder
	in.CharLimit = limit
	in.Width = width
	return in
}
