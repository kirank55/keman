package tui

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	kmodel "github.com/kirank55/keman/internal/model"
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
func (f *fakeAPI) PutPolicy(_ context.Context, _ string, _ Policy, confirm bool) (DryRun, error) {
	f.policies = append(f.policies, confirm)
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

func TestKeysShowDollars(t *testing.T) {
	m := sample(&fakeAPI{})
	view := m.View()
	if !strings.Contains(view, "laptop") || !strings.Contains(view, "$0.42") || !strings.Contains(view, "$1.5") {
		t.Fatal(view)
	}
	if strings.Contains(view, "microusd") {
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
	m, cmd := press(m, "p", "right", "right", "enter", "enter", "enter", "enter")
	if cmd == nil {
		t.Fatal("policy")
	}
	next, _ := m.Update(cmd())
	m = next.(model)
	view := m.View()
	if !strings.Contains(view, "Would disable: yes") || !strings.Contains(view, "Detections: 3") {
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
	if !strings.Contains(m.View(), "no keys match") {
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

func TestNarrowDropsCapColumn(t *testing.T) {
	m := sample(&fakeAPI{})
	m.width = 60
	view := m.View()
	if strings.Contains(view, "alert_only") {
		t.Fatal(view)
	}
	if !strings.Contains(view, "$0.42") {
		t.Fatal(view)
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
	for _, want := range []string{"127.0.0.1", "tokens in 30", "3 requests", "POST /api/v1/chat/completions", "openai/gpt-4o-mini"} {
		if !strings.Contains(view, want) {
			t.Fatalf("missing %q\n%s", want, view)
		}
	}
}

func TestSetupFromEmptyKeys(t *testing.T) {
	const secret = "sk-or-test-secret"
	f := &fakeAPI{}
	m := newModel(context.Background(), f, "http://127.0.0.1:8081")
	m.loading = false
	m.width = 120
	m.height = 40
	m.getenv = func(k string) string {
		if k == "OPENROUTER_API_KEY" {
			return secret
		}
		return ""
	}
	if !strings.Contains(m.View(), "add upstream") {
		t.Fatal(m.View())
	}
	m, _ = press(m, "a")
	if !strings.Contains(m.View(), "openrouter.ai") || !strings.Contains(m.View(), "OpenRouter is filled in") {
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
	if got != "10-27 22:04" {
		t.Fatal(got)
	}
}
