package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	kmodel "github.com/kirank55/keman/internal/model"
	"github.com/muesli/termenv"
)

type fakeAPI struct {
	keys       []Key
	creds      []Credential
	status     []string
	policies   []bool
	created    CreatedKey
	lists      int
	listErr    error
	token      string
	upDrafts   []UpstreamDraft
	credDrafts []CredentialDraft
	lastPolicy Policy
	expiries   []*time.Time
	rotations  []time.Duration
}

func (f *fakeAPI) ListKeys(context.Context) ([]Key, error) {
	f.lists++
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.keys, nil
}
func (f *fakeAPI) ListDetections(context.Context, string) ([]Detection, error) {
	return nil, nil
}
func (f *fakeAPI) ListAudit(context.Context) ([]AuditRow, error) { return nil, nil }
func (f *fakeAPI) ListUpstreams(context.Context) ([]Upstream, error) {
	return nil, nil
}
func (f *fakeAPI) ListCredentials(context.Context) ([]Credential, error) {
	return f.creds, nil
}
func (f *fakeAPI) ListAlerts(context.Context) ([]AlertDest, error) { return nil, nil }
func (f *fakeAPI) SetStatus(_ context.Context, id, action string) error {
	f.status = append(f.status, action+":"+id)
	return nil
}
func (f *fakeAPI) PutPolicy(_ context.Context, _ string, p Policy, confirm bool) (DryRun, error) {
	f.policies = append(f.policies, confirm)
	f.lastPolicy = p
	if p.Mode != kmodel.ModeAutoDisable {
		return DryRun{}, nil
	}
	if !confirm {
		return DryRun{WouldDisable: true, Detections: 3, RequestsWouldBlock: 2}, &ConfirmError{
			Message: "needs confirmation",
			Report:  DryRun{WouldDisable: true, Detections: 3, RequestsWouldBlock: 2},
		}
	}
	return DryRun{}, nil
}
func (f *fakeAPI) CreateKey(context.Context, string, string, string) (CreatedKey, error) {
	return f.created, nil
}
func (f *fakeAPI) KeyUsage(context.Context, string) (KeyUsage, error) {
	return KeyUsage{}, nil
}
func (f *fakeAPI) SetExpiry(_ context.Context, _ string, at *time.Time) error {
	f.expiries = append(f.expiries, at)
	return nil
}
func (f *fakeAPI) RotateKey(_ context.Context, id string, grace time.Duration) (Rotation, error) {
	f.rotations = append(f.rotations, grace)
	return Rotation{
		Key:     CreatedKey{ID: "new12345", Name: "laptop", Token: "kmn_rotated_once", Kind: kmodel.KindStandard},
		OldName: "laptop (rotated)", OldRevoked: grace == 0,
	}, nil
}
func (f *fakeAPI) AddUpstream(_ context.Context, d UpstreamDraft) (Upstream, error) {
	f.upDrafts = append(f.upDrafts, d)
	return Upstream{ID: "u-new", Name: d.Name, Profile: d.Profile, Host: d.Host, Port: d.Port, TLS: d.TLS}, nil
}
func (f *fakeAPI) AddCredential(_ context.Context, d CredentialDraft) (Credential, error) {
	f.credDrafts = append(f.credDrafts, d)
	return Credential{ID: "c-new", Name: d.Name, UpstreamID: d.UpstreamID, AuthStyle: "header"}, nil
}

func sample(f *fakeAPI) model {
	daily := int64(1_500_000)
	m := newModel(context.Background(), f, "http://127.0.0.1:8081")
	m.loading = false
	m.loaded = [4]bool{true, true, true, true}
	m.width = 100
	m.height = 40
	m.keys = []Key{{
		ID: "abcd1234", Name: "laptop", Status: kmodel.StatusActive, Kind: kmodel.KindStandard,
		SpendToday: 420_000,
		Policy:     &Policy{Mode: kmodel.ModeAlertOnly, DailyCapMicro: &daily},
	}}
	return m
}

func press(m model, keys ...string) (model, tea.Cmd) {
	var next tea.Model = m
	var cmd tea.Cmd
	for _, k := range keys {
		next, cmd = next.Update(keyMsg(k))
	}
	return next.(model), cmd
}

func typeText(m model, s string) model {
	for _, r := range s {
		next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
		m = next.(model)
	}
	return m
}

func keyMsg(k string) tea.KeyMsg {
	switch k {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "tab":
		return tea.KeyMsg{Type: tea.KeyTab}
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	default:
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)}
	}
}

func TestKeysShowLockExpiryAndAlerts(t *testing.T) {
	m := sample(&fakeAPI{})
	m.keys[0].Exposure = []Exposure{{Code: "network_open", Severity: "high"}, {Code: "no_expiry", Severity: "medium"}}
	m.keys[0].Detections7d = 2
	m.keys[0].LastSeen = time.Now().Add(-5 * time.Minute)
	m.keys[0].LastIP = "203.0.113.7"
	view := m.View()
	for _, want := range []string{"lock", "open", "never", "5m ago · 203.0.113.7", "1 key works from any address", "1 key never expires"} {
		if !strings.Contains(view, want) {
			t.Fatalf("missing %q\n%s", want, view)
		}
	}
	if strings.Contains(view, "$") {
		t.Fatalf("the key list should not show money\n%s", view)
	}
	m.keys[0].Policy.CIDRs = []string{"10.0.0.0/8"}
	m.keys[0].Exposure = nil
	exp := time.Now().Add(40 * 24 * time.Hour)
	m.keys[0].ExpiresAt = &exp
	view = m.View()
	if !strings.Contains(view, "ip") || !strings.Contains(view, "in 39d") || strings.Contains(view, "from any address") {
		t.Fatal(view)
	}
}

func TestDisableAndRevoke(t *testing.T) {
	f := &fakeAPI{}
	m := sample(f)
	m, cmd := press(m, "d")
	if cmd == nil {
		t.Fatal("disable")
	}
	msg := cmd()
	if len(f.status) != 1 || f.status[0] != "disable:abcd1234" {
		t.Fatal(f.status)
	}
	next, _ := m.Update(msg)
	m = next.(model)
	if !strings.Contains(m.note, "disable") {
		t.Fatal(m.note)
	}

	m = sample(f)
	m.keys[0].Status = kmodel.StatusRevoked
	m, cmd = press(m, "e")
	if cmd != nil || len(f.status) != 1 {
		t.Fatal(cmd, f.status)
	}
	if !strings.Contains(m.errMsg, "revoked") {
		t.Fatal(m.errMsg)
	}

	m = sample(f)
	m, _ = press(m, "x")
	m = typeText(m, "nope")
	m, cmd = press(m, "enter")
	if cmd != nil || len(f.status) != 1 {
		t.Fatal("partial name must not revoke", f.status)
	}
	m, _ = press(m, "esc")
	m, _ = press(m, "x")
	m = typeText(m, "laptop")
	m, cmd = press(m, "enter")
	if cmd == nil {
		t.Fatal("expected revoke")
	}
	_ = cmd()
	if f.status[len(f.status)-1] != "revoke:abcd1234" {
		t.Fatal(f.status)
	}
}

func TestTokenShownOnce(t *testing.T) {
	f := &fakeAPI{
		creds:   []Credential{{ID: "c1", Name: "primary"}},
		created: CreatedKey{ID: "k9", Name: "laptop", Token: "kmn_secret_once"},
	}
	m := sample(f)
	m.creds = f.creds
	m, _ = press(m, "n")
	m = typeText(m, "laptop")
	m, cmd := press(m, "enter", "enter", "enter")
	if cmd == nil {
		t.Fatal("create")
	}
	next, _ := m.Update(cmd())
	m = next.(model)
	if !strings.Contains(m.View(), "kmn_secret_once") {
		t.Fatal(m.View())
	}
	m, _ = press(m, "enter")
	if strings.Contains(m.View(), "kmn_secret_once") || m.token != "" {
		t.Fatal("token still on screen")
	}
}

func TestAutoDisableConfirms(t *testing.T) {
	f := &fakeAPI{}
	m := sample(f)
	m, cmd := press(m, "p", "right", "right", "enter", "enter", "enter", "enter", "enter", "enter", "enter")
	if cmd == nil {
		t.Fatal("policy")
	}
	next, _ := m.Update(cmd())
	m = next.(model)
	view := m.View()
	if !strings.Contains(view, "would disable yes") || !strings.Contains(view, "detections    3") {
		t.Fatal(view)
	}
	if len(f.policies) != 1 || f.policies[0] {
		t.Fatal(f.policies)
	}
	m, cmd = press(m, "enter")
	if cmd == nil {
		t.Fatal("confirm")
	}
	_ = cmd()
	if len(f.policies) != 2 || !f.policies[1] {
		t.Fatal(f.policies)
	}
}

func TestFilter(t *testing.T) {
	m := sample(&fakeAPI{})
	m, _ = press(m, "/")
	m = typeText(m, "nope")
	if !strings.Contains(m.View(), "No keys match") {
		t.Fatal(m.View())
	}
	m, _ = press(m, "esc")
	if !strings.Contains(m.View(), "laptop") {
		t.Fatal(m.View())
	}
}

func TestPollPausesWhileRevoking(t *testing.T) {
	f := &fakeAPI{}
	m := sample(f)
	m.overlay = overlayRevoke
	if _, fetch := m.afterTick(); fetch != nil {
		t.Fatal("fetched during revoke")
	}
	m.overlay = overlayNone
	_, fetch := m.afterTick()
	if fetch == nil {
		t.Fatal("expected fetch")
	}
	_ = fetch()
	if f.lists != 1 {
		t.Fatal(f.lists)
	}
}

func TestNarrowDropsLastSeenColumn(t *testing.T) {
	m := sample(&fakeAPI{})
	m.width = 60
	view := m.View()
	if strings.Contains(view, "last seen") {
		t.Fatal(view)
	}
	if !strings.Contains(view, "lock") || !strings.Contains(view, "open") {
		t.Fatal(view)
	}
}

func TestPolicyFormLocksAddressesAndExpiry(t *testing.T) {
	f := &fakeAPI{}
	m := sample(f)
	m, _ = press(m, "p", "down")
	m = typeText(m, "203.0.113.7/32, 10.0.0.0/8")
	m, _ = press(m, "down")
	m = typeText(m, "us de")
	m, _ = press(m, "down")
	m = typeText(m, "30d")
	m, cmd := press(m, "enter", "enter", "enter", "enter")
	if cmd == nil {
		t.Fatal("policy not saved")
	}
	if _, ok := cmd().(policyDone); !ok {
		t.Fatal("expected policyDone")
	}
	if got := strings.Join(f.lastPolicy.CIDRs, " "); got != "203.0.113.7/32 10.0.0.0/8" {
		t.Fatalf("cidrs %q", got)
	}
	if got := strings.Join(f.lastPolicy.Countries, " "); got != "US DE" {
		t.Fatalf("countries %q", got)
	}
	if f.lastPolicy.DailyCapMicro == nil || *f.lastPolicy.DailyCapMicro != 1_500_000 {
		t.Fatal("the daily cap was lost")
	}
	if len(f.expiries) != 1 || f.expiries[0] == nil || f.expiries[0].Sub(time.Now()) < 29*24*time.Hour {
		t.Fatalf("expiry %v", f.expiries)
	}

	f = &fakeAPI{}
	m = sample(f)
	m, cmd = press(m, "p", "enter", "enter", "enter", "enter", "enter", "enter", "enter")
	_ = cmd()
	if len(f.expiries) != 0 {
		t.Fatal("an unchanged expiry was sent")
	}
}

func TestRotateShowsTheNewTokenOnce(t *testing.T) {
	f := &fakeAPI{}
	m := sample(f)
	m, _ = press(m, "r")
	if m.overlay != overlayRotate || !strings.Contains(m.View(), "24 hours") {
		t.Fatal(m.View())
	}
	m, _ = press(m, "left")
	if !strings.Contains(m.View(), "revoke it now") {
		t.Fatal(m.View())
	}
	m, cmd := press(m, "enter")
	next, _ := m.Update(cmd())
	m = next.(model)
	view := m.View()
	if len(f.rotations) != 1 || f.rotations[0] != 0 {
		t.Fatal(f.rotations)
	}
	if !strings.Contains(view, "kmn_rotated_once") || !strings.Contains(view, "old key is revoked") {
		t.Fatal(view)
	}
	m, _ = press(m, "enter")
	if strings.Contains(m.View(), "kmn_rotated_once") {
		t.Fatal("token still on screen")
	}
}

func TestRunRejectsPipe(t *testing.T) {
	err := Run(context.Background(), &fakeAPI{}, "http://127.0.0.1:8081", strings.NewReader(""), &strings.Builder{})
	if err != ErrNotTerminal {
		t.Fatal(err)
	}
}

func TestDetailShowsUsage(t *testing.T) {
	m := sample(&fakeAPI{})
	m.overlay = overlayDetail
	m.detailID = "abcd1234"
	m.detailLoaded = true
	when := time.Date(2026, 10, 27, 16, 58, 0, 0, time.UTC)
	cost := int64(1_500)
	m.detailUsage = KeyUsage{
		Requests: 3, TokensIn: 30, TokensOut: 10, Priced: 3, CostMicro: 1_500, LastSeen: when,
		Clients: []UsageClient{{IP: "127.0.0.1", Requests: 3, LastSeen: when}},
		Models: []UsageModel{{
			Model: "openai/gpt-4o-mini", Requests: 3, TokensIn: 30, TokensOut: 10, CostMicro: 1_500, Priced: 3,
		}},
		Recent: []UsageRequest{{
			Time: when, IP: "127.0.0.1", Status: 200, LatencyMS: 1885,
			Operation: "POST /api/v1/chat/completions", Model: "openai/gpt-4o-mini",
			TokensIn: 10, TokensOut: 4, CostMicro: &cost,
		}},
	}
	view := m.View()
	for _, want := range []string{"127.0.0.1", "in 30 · out 10", "3 requests", "POST /api/v1/chat/completions", "openai/gpt-4o-mini"} {
		if !strings.Contains(view, want) {
			t.Fatalf("missing %q\n%s", want, view)
		}
	}
}

func TestDetailSplitShowsFindings(t *testing.T) {
	lipgloss.SetColorProfile(termenv.ANSI256)
	m := sample(&fakeAPI{})
	m.overlay = overlayDetail
	m.detailID = "abcd1234"
	m.detailLoaded = true
	m.width = 100
	m.keys[0].Exposure = []Exposure{
		{Code: "network_open", Severity: "high"},
		{Code: "no_expiry", Severity: "medium"},
	}
	when := time.Date(2026, 10, 28, 11, 30, 0, 0, time.UTC)
	cost := int64(2)
	m.detailUsage = KeyUsage{
		Requests: 7, TokensIn: 56, TokensOut: 7, CostMicro: 2, Priced: 5, LastSeen: when,
		Clients: []UsageClient{{IP: "127.0.0.1", Requests: 7, LastSeen: when}},
		Recent: []UsageRequest{{
			Time: when, IP: "127.0.0.1", Status: 200, LatencyMS: 2,
			Operation: "POST /v1/chat/completions", Model: "gpt-4o-mini",
			TokensIn: 8, TokensOut: 1, CostMicro: &cost,
		}},
	}
	view := m.View()
	for _, want := range []string{"open network", "set --cidr <egress>/32", "no expiry", "key expiry 90d", "gpt-4o-mini", "╭", "╰"} {
		if !strings.Contains(view, want) {
			t.Fatalf("missing %q\n%s", want, view)
		}
	}
	if strings.Contains(view, "anyone who has it can call it") {
		t.Fatal("the phrase does not fit the rail at 100 columns")
	}
	var openLine string
	for _, line := range strings.Split(view, "\n") {
		if strings.Contains(line, "open network") {
			openLine = line
			break
		}
	}
	if !strings.Contains(openLine, "48;") {
		t.Fatalf("finding bar has no background\n%s", openLine)
	}
	assertFits(t, "detail findings", m)
	bottoms := 0
	for _, line := range strings.Split(view, "\n") {
		if strings.Count(line, "╰") == 2 {
			bottoms++
		}
	}
	if bottoms != 1 {
		t.Fatalf("panels should close on one shared row, found %d\n%s", bottoms, view)
	}

	m.width = 140
	if !strings.Contains(m.View(), "anyone who has it can call it") {
		t.Fatal("wide rail should keep the phrase on the bar")
	}
	assertFits(t, "detail findings", m)
}

func TestSetupFromEmptyKeys(t *testing.T) {
	const secret = "sk-or-test-secret"
	f := &fakeAPI{}
	m := newModel(context.Background(), f, "http://127.0.0.1:8081")
	m.loading = false
	m.loaded = [4]bool{true, true, true, true}
	m.width = 120
	m.height = 40
	m.getenv = func(k string) string {
		if k == "OPENROUTER_API_KEY" {
			return secret
		}
		return ""
	}
	if !strings.Contains(m.View(), "Press a to add an upstream") {
		t.Fatal(m.View())
	}
	m, _ = press(m, "a")
	if !strings.Contains(m.View(), "openrouter.ai") || !strings.Contains(m.View(), "OpenRouter is only a suggestion") {
		t.Fatal(m.View())
	}
	m, cmd := press(m, "enter", "enter", "enter", "enter", "enter", "enter")
	if cmd == nil {
		t.Fatal("upstream")
	}
	next, _ := m.Update(cmd())
	m = next.(model)
	if len(f.upDrafts) != 1 {
		t.Fatal(f.upDrafts)
	}
	d := f.upDrafts[0]
	if d.Name != "openrouter" || d.Profile != "openai" || d.Host != "openrouter.ai" || d.Port != 443 || !d.TLS {
		t.Fatalf("%+v", d)
	}
	if len(d.Paths) != 3 || d.Paths[0] != "POST /api/v1/chat/completions" || d.Paths[2] != "GET /api/v1/models/*" {
		t.Fatalf("%+v", d.Paths)
	}
	if m.overlay != overlayCredential {
		t.Fatalf("overlay %d", m.overlay)
	}
	if strings.Contains(m.View(), secret) {
		t.Fatal(m.View())
	}
	m, cmd = press(m, "enter", "enter", "enter", "enter")
	if cmd == nil {
		t.Fatal("credential")
	}
	next, _ = m.Update(cmd())
	m = next.(model)
	if len(f.credDrafts) != 1 || f.credDrafts[0].Secret != secret || f.credDrafts[0].UpstreamID != "u-new" || f.credDrafts[0].Name != "primary" {
		t.Fatalf("%+v", f.credDrafts)
	}
	if strings.Contains(m.View(), secret) || m.credSecret.Value() != "" {
		t.Fatal("secret retained")
	}
	if m.overlay != overlayCreate {
		t.Fatalf("overlay %d", m.overlay)
	}
}

func TestTypedSecretIsMaskedAndCleared(t *testing.T) {
	const secret = "sk-typed-secret"
	f := &fakeAPI{}
	m := newModel(context.Background(), f, "http://127.0.0.1:8081")
	m.loading = false
	m.width = 120
	m.height = 40
	m.ups = []Upstream{{ID: "u1", Name: "openrouter"}}
	m, _ = press(m, "c")
	if m.overlay != overlayCredential || m.credMode != 1 {
		t.Fatalf("overlay %d mode %d", m.overlay, m.credMode)
	}
	m, _ = press(m, "enter", "enter", "enter")
	m = typeText(m, secret)
	if strings.Contains(m.View(), secret) {
		t.Fatal(m.View())
	}
	m, cmd := press(m, "enter")
	if cmd == nil {
		t.Fatal(m.errMsg)
	}
	next, _ := m.Update(cmd())
	m = next.(model)
	if strings.Contains(m.View(), secret) || m.credSecret.Value() != "" {
		t.Fatal("secret retained")
	}
	if len(f.credDrafts) != 1 || f.credDrafts[0].Secret != secret {
		t.Fatalf("%+v", f.credDrafts)
	}
}

func TestEmptySecretDoesNotSubmit(t *testing.T) {
	f := &fakeAPI{}
	m := newModel(context.Background(), f, "http://127.0.0.1:8081")
	m.loading = false
	m.width = 120
	m.height = 40
	m.ups = []Upstream{{ID: "u1", Name: "openrouter"}}
	m, cmd := press(m, "c", "enter", "enter", "enter", "enter")
	if cmd != nil || len(f.credDrafts) != 0 {
		t.Fatal(cmd, f.credDrafts)
	}
	if !strings.Contains(m.errMsg, "api key") {
		t.Fatal(m.errMsg)
	}
}

func adminPrompt(f *fakeAPI) model {
	m := newModel(context.Background(), f, "http://127.0.0.1:8081")
	m.loading = false
	m.width = 100
	m.height = 30
	m.overlay = overlayAdmin
	m.setToken = func(token string) { f.token = token }
	return m
}

func TestAdminTokenIsMasked(t *testing.T) {
	const token = "kma_live_token_value"
	f := &fakeAPI{}
	m := adminPrompt(f)
	if _, fetch := m.afterTick(); fetch != nil {
		t.Fatal("polled before the admin token")
	}
	if _, ok := m.Init()().(focusAdminMsg); !ok {
		t.Fatal("init should focus the token field")
	}
	next, _ := m.Update(focusAdminMsg{})
	m = next.(model)
	m = typeText(m, token)
	if strings.Contains(m.View(), token) {
		t.Fatal(m.View())
	}
	m, cmd := press(m, "enter")
	if cmd == nil {
		t.Fatal(m.errMsg)
	}
	next, _ = m.Update(cmd())
	m = next.(model)
	if f.token != token || m.adminInput.Value() != "" || m.overlay != overlayNone {
		t.Fatalf("token %q overlay %d input %q", f.token, m.overlay, m.adminInput.Value())
	}
	if strings.Contains(m.View(), token) {
		t.Fatal("token still on screen")
	}
}

func TestAdminTokenRejectedIsCleared(t *testing.T) {
	const token = "kma_live_token_value"
	f := &fakeAPI{listErr: &callError{status: 401, msg: "The admin token is invalid."}}
	m := adminPrompt(f)
	m.adminInput.Focus()
	m = typeText(m, token)
	m, cmd := press(m, "enter")
	if cmd == nil {
		t.Fatal(m.errMsg)
	}
	next, _ := m.Update(cmd())
	m = next.(model)
	if f.token != "" || m.overlay != overlayAdmin || strings.Contains(m.View(), token) {
		t.Fatalf("token %q overlay %d\n%s", f.token, m.overlay, m.View())
	}
	if !strings.Contains(m.errMsg, "invalid") {
		t.Fatal(m.errMsg)
	}
}

func TestAdminTokenRequiredAndRetried(t *testing.T) {
	f := &fakeAPI{}
	m := adminPrompt(f)
	m, cmd := press(m, "enter")
	if cmd != nil || f.lists != 0 || !strings.Contains(m.errMsg, "admin token") {
		t.Fatalf("cmd %v lists %d err %s", cmd, f.lists, m.errMsg)
	}

	const token = "kma_live_token_value"
	f.listErr = errors.New("admin API is not reachable at http://127.0.0.1:8081; run keman serve")
	m.adminInput.Focus()
	m = typeText(m, token)
	m, cmd = press(m, "enter")
	next, _ := m.Update(cmd())
	m = next.(model)
	if f.token != token || m.overlay != overlayAdmin || strings.Contains(m.View(), token) {
		t.Fatalf("token %q overlay %d\n%s", f.token, m.overlay, m.View())
	}
	m, cmd = press(m, "enter")
	if cmd == nil {
		t.Fatal("retry")
	}
	_ = cmd()
	if f.lists != 2 || f.token != token {
		t.Fatalf("lists %d token %q", f.lists, f.token)
	}
}

func TestFmtTimeUTC(t *testing.T) {
	got := fmtTime(time.Date(2026, 10, 27, 15, 4, 0, 0, time.FixedZone("local", -7*3600)))
	if got != "2026-10-27 22:04 UTC" {
		t.Fatal(got)
	}
}

// richSample fills every screen with long values, to check the layout.
func richSample() model {
	m := sample(&fakeAPI{})
	when := time.Date(2026, 10, 27, 16, 58, 0, 0, time.UTC)
	m.keys = append(m.keys, Key{
		ID: "zzzz9999", Name: "a-very-long-virtual-key-name-for-ci", Status: kmodel.StatusActive, Kind: kmodel.KindCanary,
	})
	m.dets = []Detection{{Time: when, KeyID: "abcd1234", Rule: "repeated_allowlist_violations", Severity: "medium"}}
	m.audits = []AuditRow{{Time: when, Actor: "admin-token-with-a-long-actor-name", Action: "key.create", Target: "abcd1234"}}
	m.ups = []Upstream{{ID: "u1", Name: "openrouter", Profile: "openai", Host: "openrouter.ai", Port: 443, TLS: true}}
	m.creds = []Credential{{ID: "c1", Name: "primary", UpstreamID: "u1", AuthStyle: "header", Last4: "abcd"}}
	m.alerts = []AlertDest{{ID: "a1", Kind: "webhook", URL: "https://example.invalid/a/very/long/webhook/path/that/goes/on"}}
	return m
}

func assertFits(t *testing.T, name string, m model) {
	t.Helper()
	view := m.View()
	for i, line := range strings.Split(view, "\n") {
		if w := lipgloss.Width(line); w > m.width {
			t.Fatalf("%s at %d columns: line %d is %d wide\n%s", name, m.width, i, w, view)
		}
	}
	if m.height > 0 {
		if n := strings.Count(view, "\n") + 1; n != m.height {
			t.Fatalf("%s at %d columns: %d lines, want %d", name, m.width, n, m.height)
		}
	}
}

func TestViewsFitTheTerminal(t *testing.T) {
	for _, width := range []int{100, 60} {
		for _, s := range []screen{screenKeys, screenDetections, screenAudit, screenSetup} {
			m := richSample()
			m.width = width
			m.screen = s
			assertFits(t, fmt.Sprintf("screen %d", s), m)
		}
		m := richSample()
		m.width = width
		m, _ = press(m, "a")
		assertFits(t, "upstream form", m)

		m = richSample()
		m.width = width
		m.overlay = overlayDetail
		m.detailID = "abcd1234"
		m.detailLoaded = true
		m.detailUsage = KeyUsage{Requests: 1, Recent: []UsageRequest{{
			Operation: "POST /api/v1/a/very/long/operation/path/that/does/not/fit/in/sixty/columns", Status: 200,
		}}}
		assertFits(t, "detail", m)
	}
}

func TestFirstPaintSaysLoading(t *testing.T) {
	m := newModel(context.Background(), &fakeAPI{}, "http://127.0.0.1:8081")
	m.width, m.height = 100, 20
	view := m.View()
	if !strings.Contains(view, "loading…") || strings.Contains(view, "No virtual keys yet") {
		t.Fatal(view)
	}
}

func TestActionErrorSurvivesPoll(t *testing.T) {
	m := sample(&fakeAPI{})
	next, _ := m.Update(actionDone{action: "disable", name: "laptop", err: errors.New("store_unavailable")})
	m = next.(model)
	next, _ = m.Update(keysLoaded{gen: m.gen, keys: m.keys})
	m = next.(model)
	if !strings.Contains(m.View(), "store_unavailable") {
		t.Fatal("a successful poll cleared the action error")
	}
	m, _ = press(m, "j")
	if strings.Contains(m.View(), "store_unavailable") {
		t.Fatal("the next key should clear the error")
	}
}

func TestPollErrorClearsWhenThePollRecovers(t *testing.T) {
	m := sample(&fakeAPI{})
	next, _ := m.Update(keysLoaded{gen: m.gen, err: errors.New("connection refused")})
	m = next.(model)
	if !strings.Contains(m.View(), "connection refused") {
		t.Fatal(m.View())
	}
	next, _ = m.Update(keysLoaded{gen: m.gen, keys: m.keys})
	m = next.(model)
	if strings.Contains(m.View(), "connection refused") {
		t.Fatal(m.View())
	}
}

func TestNoteKeepsTheFooter(t *testing.T) {
	m := sample(&fakeAPI{})
	next, _ := m.Update(actionDone{action: "disable", name: "laptop"})
	m = next.(model)
	view := m.View()
	if !strings.Contains(view, "disable laptop") || !strings.Contains(view, "q quit") {
		t.Fatal(view)
	}
}

func TestDetailScrollStopsAtTheEnd(t *testing.T) {
	m := sample(&fakeAPI{})
	m.height = 12
	m.overlay = overlayDetail
	m.detailID = "abcd1234"
	m.detailLoaded = true
	recent := make([]UsageRequest, 40)
	for i := range recent {
		recent[i] = UsageRequest{Operation: "POST /v1/chat/completions", Status: 200, Model: "m"}
	}
	m.detailUsage = KeyUsage{Requests: len(recent), Recent: recent}
	for i := 0; i < 200; i++ {
		m, _ = press(m, "j")
	}
	end := m.scroll
	if end == 0 || end != m.maxScroll(m.renderDetail()) {
		t.Fatalf("scroll %d, max %d", end, m.maxScroll(m.renderDetail()))
	}
	m, _ = press(m, "k")
	if m.scroll != end-1 {
		t.Fatalf("one k should move up one line, got %d from %d", m.scroll, end)
	}
}

func TestFilterIsPerView(t *testing.T) {
	m := richSample()
	m, _ = press(m, "/")
	m = typeText(m, "nope")
	m, _ = press(m, "enter")
	if !strings.Contains(m.View(), "No keys match") {
		t.Fatal(m.View())
	}
	m.screen = screenDetections
	if !strings.Contains(m.View(), "repeated_allowlist") {
		t.Fatal("the keys filter hid detections\n" + m.View())
	}
}

func TestQIsTypedInTextFieldsAndQuitsElsewhere(t *testing.T) {
	m := sample(&fakeAPI{})
	m.keys[0].Name = "quartz"
	m, _ = press(m, "x")
	m, cmd := press(m, "q")
	if m.overlay != overlayRevoke || m.revokeInput.Value() != "q" {
		t.Fatalf("q was not typed into revoke: %q", m.revokeInput.Value())
	}
	if cmd != nil && isQuit(cmd) {
		t.Fatal("q quit from the revoke field")
	}
	m, _ = press(m, "esc")
	if m.overlay != overlayNone {
		t.Fatal("esc should cancel revoke")
	}
	if _, cmd = press(m, "q"); cmd == nil || !isQuit(cmd) {
		t.Fatal("q should quit from the keys view")
	}
}

func isQuit(cmd tea.Cmd) bool {
	_, ok := cmd().(tea.QuitMsg)
	return ok
}

func TestCanaryStatusAndKindAreSeparate(t *testing.T) {
	m := richSample()
	view := m.View()
	line := ""
	for _, l := range strings.Split(view, "\n") {
		if strings.Contains(l, "a-very-long") {
			line = l
		}
	}
	if !strings.Contains(line, "active") || !strings.Contains(line, "canary") {
		t.Fatalf("canary row %q", line)
	}
	if !strings.Contains(line, "…") {
		t.Fatalf("long name should be cut with an ellipsis: %q", line)
	}
}

func TestEnterOnDetectionOpensItsKey(t *testing.T) {
	m := richSample()
	m.screen = screenDetections
	m, _ = press(m, "enter")
	if m.overlay != overlayDetail || m.detailID != "abcd1234" {
		t.Fatalf("overlay %d detail %q", m.overlay, m.detailID)
	}
	m, _ = press(m, "esc")
	if m.screen != screenDetections || m.overlay != overlayNone {
		t.Fatal("esc should return to detections")
	}
}

func TestProfileSwapsUntouchedPreset(t *testing.T) {
	m := sample(&fakeAPI{})
	m, _ = press(m, "a", "down", "right")
	if m.upHost.Value() != "api.anthropic.com" {
		t.Fatalf("host %q", m.upHost.Value())
	}
	m, _ = press(m, "down")
	m = typeText(m, "x")
	m, _ = press(m, "up", "right")
	if m.upHost.Value() != "api.anthropic.comx" {
		t.Fatalf("an edited host was replaced: %q", m.upHost.Value())
	}
}

func TestLastFieldFooterSaysSave(t *testing.T) {
	m := sample(&fakeAPI{})
	m, _ = press(m, "p")
	if !strings.Contains(m.View(), "enter next") {
		t.Fatal(m.View())
	}
	m, _ = press(m, "up")
	if !strings.Contains(m.View(), "enter save") {
		t.Fatal(m.View())
	}
}

func TestUSDHasCents(t *testing.T) {
	for micro, want := range map[int64]string{0: "$0.00", 1_500_000: "$1.50", 420_000: "$0.42", 1_500: "$0.0015", 20_000_000: "$20.00"} {
		if got := usd(micro); got != want {
			t.Errorf("usd(%d) = %q, want %q", micro, got, want)
		}
	}
}

func click(m model, x, y int) (model, tea.Cmd) {
	next, cmd := m.Update(tea.MouseMsg{X: x, Y: y, Action: tea.MouseActionPress, Button: tea.MouseButtonLeft})
	return next.(model), cmd
}

func TestClickTabSwitchesScreen(t *testing.T) {
	m := sample(&fakeAPI{})
	line := strings.Split(m.View(), "\n")[0]
	x := lipgloss.Width(line[:strings.Index(line, "3 audit")])
	m, _ = click(m, x+1, 0)
	if m.screen != screenAudit {
		t.Fatalf("screen = %v, want audit", m.screen)
	}
}

func TestClickRowSelectsThenOpens(t *testing.T) {
	m := sample(&fakeAPI{})
	m.keys = append(m.keys, Key{ID: "efgh5678", Name: "ci", Status: kmodel.StatusActive, Kind: kmodel.KindStandard})
	var y int
	for i, l := range strings.Split(m.View(), "\n") {
		if strings.Contains(l, "ci ") {
			y = i
		}
	}
	m, _ = click(m, 5, y)
	if m.cursor != 1 || m.overlay != overlayNone {
		t.Fatalf("first click: cursor %d overlay %v", m.cursor, m.overlay)
	}
	m, _ = click(m, 5, y)
	if m.overlay != overlayDetail {
		t.Fatalf("second click should open detail, overlay %v", m.overlay)
	}
}

func TestClickOverlayButtons(t *testing.T) {
	m := sample(&fakeAPI{})
	m = m.openRotate()
	lines := strings.Split(m.View(), "\n")
	var y, cx int
	for i, l := range lines {
		if strings.Contains(l, "Cancel") {
			y, cx = i, lipgloss.Width(l[:strings.Index(l, "Cancel")])
		}
	}
	if y == 0 {
		t.Fatalf("no button row\n%s", m.View())
	}
	m, _ = click(m, cx+1, y)
	if m.overlay != overlayNone {
		t.Fatalf("cancel should close the dialog, overlay %v", m.overlay)
	}
	m = m.openRotate()
	_, cmd := click(m, 2, y)
	if cmd == nil {
		t.Fatal("rotate button should start the rotation")
	}
	m = m.openRevoke()
	m, _ = click(m, 2, y)
	if m.overlay != overlayRevoke {
		t.Fatal("revoke button must not act without the typed name")
	}
}
