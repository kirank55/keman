package tui

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/kirank55/keman/internal/expiry"
	kmodel "github.com/kirank55/keman/internal/model"
	"github.com/kirank55/keman/internal/money"
	"github.com/kirank55/keman/internal/preset"
)

type tickMsg struct{}

type keysLoaded struct {
	gen  int
	keys []Key
	err  error
}

type detsLoaded struct {
	gen   int
	keyID string
	rows  []Detection
	err   error
}

type auditLoaded struct {
	gen  int
	rows []AuditRow
	err  error
}

type setupLoaded struct {
	gen    int
	ups    []Upstream
	creds  []Credential
	alerts []AlertDest
	err    error
}

type actionDone struct {
	action string
	name   string
	err    error
}

type policyDone struct {
	err error
}

type createdDone struct {
	key  CreatedKey
	note string
	err  error
}

type upstreamDone struct {
	up  Upstream
	err error
}

type credentialDone struct {
	cred Credential
	err  error
}

type adminReady struct {
	keys []Key
	err  error
}

type focusAdminMsg struct{}

// upstreamChoice is one value of the platform field: a preset, or a custom
// upstream on one profile. An empty paths field means the preset's list.
type upstreamChoice struct {
	label, preset, profile string
	name, host, port       string
	tls                    bool
	paths                  int
}

// upstreamChoices puts OpenRouter first: it is the suggestion for a new
// install. Custom entries come last.
var upstreamChoices = func() []upstreamChoice {
	var out []upstreamChoice
	add := func(p preset.Preset) {
		out = append(out, upstreamChoice{
			label: p.Title, preset: p.Name, profile: p.Profile,
			name: p.Name, host: p.Host, port: strconv.Itoa(p.Port), tls: p.TLS, paths: len(p.Paths),
		})
	}
	first, _ := preset.Get("openrouter")
	add(first)
	for _, p := range preset.All() {
		if p.Name != first.Name {
			add(p)
		}
	}
	for _, prof := range []string{"openai", "anthropic", "generic"} {
		out = append(out, upstreamChoice{label: "custom " + prof, profile: prof, port: "443", tls: true})
	}
	return out
}()

func (m *model) applyPreset(c upstreamChoice) {
	m.upName.SetValue(c.name)
	m.upHost.SetValue(c.host)
	m.upPort.SetValue(c.port)
	m.upPaths.SetValue("")
	switch {
	case c.paths > 0:
		m.upPaths.Placeholder = fmt.Sprintf("the %s list (%d paths)", c.label, c.paths)
	case c.profile == "generic":
		m.upPaths.Placeholder = "POST /path"
	default:
		m.upPaths.Placeholder = "the built-in " + c.profile + " list"
	}
	m.upTLS = c.tls
	m.upName.CursorEnd()
	m.upHost.CursorEnd()
	m.upPort.CursorEnd()
}

// upstreamIs reports whether the form still holds choice c, unedited.
func (m model) upstreamIs(c upstreamChoice) bool {
	return m.upName.Value() == c.name && m.upHost.Value() == c.host &&
		m.upPort.Value() == c.port && m.upPaths.Value() == "" && m.upTLS == c.tls
}

// credentialEnv is the variable a credential for up is usually read from.
func credentialEnv(up Upstream) string {
	if p, ok := preset.Get(up.Preset); ok {
		return p.Env
	}
	switch up.Profile {
	case "anthropic":
		return "ANTHROPIC_API_KEY"
	case "openai":
		return "OPENAI_API_KEY"
	}
	return "API_KEY"
}

func (m model) Init() tea.Cmd {
	if m.overlay == overlayAdmin {
		return func() tea.Msg { return focusAdminMsg{} }
	}
	return tea.Batch(m.fetchKeys(), m.fetchSetup(), scheduleTick())
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil
	case focusAdminMsg:
		if m.overlay != overlayAdmin {
			return m, nil
		}
		return m.focusAdmin()
	case tea.KeyMsg:
		// Feedback lasts until the next key, not the next poll.
		m.note = ""
		m.errMsg = ""
		m.errFromPoll = false
		return m.onKey(msg)
	case tea.MouseMsg:
		return m.onMouse(msg)
	case tickMsg:
		next, fetch := m.afterTick()
		return next, tea.Batch(scheduleTick(), fetch)
	case keysLoaded:
		if msg.gen != m.gen {
			return m, nil
		}
		m.loading = false
		if msg.err != nil {
			m.pollErr(msg.err)
			return m, nil
		}
		m.keys = msg.keys
		m.loaded[screenKeys] = true
		m.clearPollErr()
		m.clamp()
		return m, nil
	case detsLoaded:
		if msg.gen != m.gen {
			return m, nil
		}
		m.loading = false
		if msg.err != nil {
			m.pollErr(msg.err)
			return m, nil
		}
		if msg.keyID != "" {
			if msg.keyID == m.detailID {
				m.detailDets = msg.rows
			}
		} else {
			m.dets = msg.rows
			m.loaded[screenDetections] = true
			m.clamp()
		}
		m.clearPollErr()
		return m, nil
	case usageLoaded:
		if msg.keyID != m.detailID {
			return m, nil
		}
		m.loading = false
		// A fetch started on the key can land after a name was saved.
		// Keep the name on screen; the next refresh picks up the stored one.
		if m.overlay == overlayClient && m.detailLoaded {
			return m, nil
		}
		if msg.err != nil {
			m.pollErr(msg.err)
			return m, nil
		}
		m.detailUsage = msg.usage
		m.detailLoaded = true
		m.clearPollErr()
		return m, nil
	case clientNamed:
		m.loading = false
		if msg.err != nil {
			m.errMsg = errText(msg.err)
			return m, nil
		}
		m.applyClientName(msg.ip, msg.name)
		m.clientEditing = false
		m.clientInput.Blur()
		m.errMsg = ""
		if msg.name == "" {
			m.note = "cleared name for " + msg.ip
		} else {
			m.note = "named " + msg.ip + " " + msg.name
		}
		return m, nil
	case auditLoaded:
		if msg.gen != m.gen {
			return m, nil
		}
		m.loading = false
		if msg.err != nil {
			m.pollErr(msg.err)
			return m, nil
		}
		m.audits = msg.rows
		m.loaded[screenAudit] = true
		m.clearPollErr()
		m.clamp()
		return m, nil
	case setupLoaded:
		if msg.gen != m.gen {
			return m, nil
		}
		m.loading = false
		if msg.err != nil {
			m.pollErr(msg.err)
			return m, nil
		}
		m.ups = msg.ups
		m.creds = msg.creds
		m.alerts = msg.alerts
		m.loaded[screenSetup] = true
		m.clearPollErr()
		return m, nil
	case actionDone:
		m.loading = false
		if msg.err != nil {
			m.errMsg = errText(msg.err)
			return m, nil
		}
		m.errMsg = ""
		m.note = msg.action + " " + msg.name
		if msg.action == "revoke" {
			m.overlay = overlayNone
			m.revokeInput.SetValue("")
			m.revokeInput.Blur()
		}
		m.loading = true
		m.gen++
		return m, m.fetchCurrent()
	case policyDone:
		m.loading = false
		var conf *ConfirmError
		if msg.err != nil && asConfirm(msg.err, &conf) {
			m.confirmReport = conf.Report
			m.overlay = overlayConfirm
			m.errMsg = ""
			return m, nil
		}
		if msg.err != nil {
			m.errMsg = errText(msg.err)
			return m, nil
		}
		m.errMsg = ""
		m.note = "policy saved"
		m.overlay = overlayNone
		m.policyConfirm = false
		m.loading = true
		m.gen++
		return m, m.fetchCurrent()
	case credsLoaded:
		if msg.err != nil {
			m.errMsg = errText(msg.err)
			return m, nil
		}
		m.creds = msg.creds
		if len(m.creds) == 0 && m.overlay == overlayCreate {
			m.errMsg = "press c to add a credential"
		}
		return m, nil
	case createdDone:
		m.loading = false
		if msg.err != nil {
			m.errMsg = errText(msg.err)
			return m, nil
		}
		m.errMsg = ""
		m.token = msg.key.Token
		m.tokenName = msg.key.Name
		m.tokenKind = msg.key.Kind
		m.tokenNote = msg.note
		if m.tokenName == "" {
			m.tokenName = msg.key.ID
		}
		m.nameInput.SetValue("")
		m.overlay = overlayToken
		return m, nil
	case upstreamDone:
		m.loading = false
		if msg.err != nil {
			m.errMsg = errText(msg.err)
			return m, nil
		}
		m.errMsg = ""
		m.ups = append(m.ups, msg.up)
		m.credUp = len(m.ups) - 1
		m.gen++
		if len(m.creds) == 0 {
			return m.openCredential()
		}
		m.note = "added upstream " + msg.up.Name
		m.overlay = overlayNone
		m.loading = true
		return m, m.fetchSetup()
	case credentialDone:
		m.loading = false
		if msg.err != nil {
			m.errMsg = errText(msg.err)
			return m, nil
		}
		m.errMsg = ""
		m.credSecret.SetValue("")
		m.creds = append(m.creds, msg.cred)
		m.createCred = len(m.creds) - 1
		m.gen++
		if len(m.keys) == 0 {
			return m.openCreate()
		}
		m.note = "added credential " + msg.cred.Name
		m.overlay = overlayNone
		m.loading = true
		return m, m.fetchSetup()
	case adminReady:
		if msg.err != nil {
			if unauthorized(msg.err) {
				m.applyToken("")
				m.adminHeld = false
			}
			m.errMsg = errText(msg.err)
			return m.focusAdmin()
		}
		m.keys = msg.keys
		m.loaded[screenKeys] = true
		m.errMsg = ""
		m.adminInput.SetValue("")
		m.overlay = overlayNone
		m.loading = true
		return m, tea.Batch(m.fetchSetup(), scheduleTick())
	}
	return m, nil
}

func asConfirm(err error, dest **ConfirmError) bool {
	conf, ok := err.(*ConfirmError)
	if !ok || conf == nil {
		return false
	}
	*dest = conf
	return true
}

func (m model) afterTick() (model, tea.Cmd) {
	if m.busy() || m.loading {
		return m, nil
	}
	m.loading = true
	return m, m.fetchCurrent()
}

func (m model) busy() bool {
	switch m.overlay {
	case overlayPolicy, overlayRevoke, overlayRotate, overlayCreate, overlayUpstream, overlayCredential, overlayToken, overlayConfirm, overlayAdmin, overlayClient:
		return true
	}
	return m.filtering
}

func scheduleTick() tea.Cmd {
	return tea.Tick(2*time.Second, func(time.Time) tea.Msg { return tickMsg{} })
}

func (m model) onKey(msg tea.KeyMsg) (model, tea.Cmd) {
	s := msg.String()
	if s == "ctrl+c" {
		m.token = ""
		m.credSecret.SetValue("")
		m.adminInput.SetValue("")
		return m, tea.Quit
	}
	if s == "q" && !m.textFocused() {
		m.token = ""
		m.credSecret.SetValue("")
		m.adminInput.SetValue("")
		return m, tea.Quit
	}
	if m.filtering {
		return m.onFilter(msg)
	}
	switch m.overlay {
	case overlayHelp:
		if s == "esc" || s == "?" {
			m.overlay = m.helpFrom
		}
		return m, nil
	case overlayToken:
		return m.onToken(s)
	case overlayRevoke:
		return m.onRevoke(msg)
	case overlayRotate:
		return m.onRotate(msg.String())
	case overlayConfirm:
		return m.onConfirm(s)
	case overlayPolicy:
		return m.onPolicy(msg)
	case overlayCreate:
		return m.onCreate(msg)
	case overlayUpstream:
		return m.onUpstream(msg)
	case overlayCredential:
		return m.onCredential(msg)
	case overlayAdmin:
		return m.onAdmin(msg)
	case overlayClient:
		return m.onClient(msg)
	case overlayDetail:
		return m.onDetail(msg)
	}
	return m.onScreen(msg)
}

func (m model) onToken(s string) (model, tea.Cmd) {
	switch s {
	case "enter", "esc":
		m.token = ""
		m.tokenName = ""
		m.tokenKind = ""
		m.tokenNote = ""
		m.overlay = overlayNone
		m.loading = true
		m.gen++
		return m, m.fetchCurrent()
	default:
		return m, nil
	}
}

func (m model) onFilter(msg tea.KeyMsg) (model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.filtering = false
		m.filters[m.screen] = ""
		m.filterInput.SetValue("")
		m.filterInput.Blur()
		m.cursor = 0
		m.clamp()
		return m, nil
	case "enter":
		m.filtering = false
		m.filters[m.screen] = strings.TrimSpace(m.filterInput.Value())
		m.filterInput.Blur()
		m.cursor = 0
		m.clamp()
		return m, nil
	default:
		var cmd tea.Cmd
		m.filterInput, cmd = m.filterInput.Update(msg)
		m.filters[m.screen] = m.filterInput.Value()
		m.cursor = 0
		m.clamp()
		return m, cmd
	}
}

func (m model) onScreen(msg tea.KeyMsg) (model, tea.Cmd) {
	switch msg.String() {
	case "1":
		return m.switchScreen(screenKeys)
	case "2":
		return m.switchScreen(screenDetections)
	case "3":
		return m.switchScreen(screenAudit)
	case "4":
		return m.switchScreen(screenSetup)
	case "tab":
		return m.switchScreen(screen((int(m.screen) + 1) % 4))
	case "shift+tab":
		return m.switchScreen(screen((int(m.screen) + 3) % 4))
	case "?":
		m.helpFrom = overlayNone
		m.overlay = overlayHelp
		return m, nil
	case "j", "down":
		if m.screen == screenSetup {
			m.scroll = min(m.scroll+1, m.maxScroll(m.renderSetup()))
			return m, nil
		}
		return m.move(1), nil
	case "k", "up":
		if m.screen == screenSetup {
			if m.scroll > 0 {
				m.scroll--
			}
			return m, nil
		}
		return m.move(-1), nil
	case "/":
		if m.screen == screenSetup {
			return m, nil
		}
		m.filtering = true
		m.filterInput.SetValue(m.filter())
		return m, m.filterInput.Focus()
	case "enter":
		switch m.screen {
		case screenKeys:
			return m.openDetail()
		case screenDetections:
			rows := m.visibleDets()
			if m.cursor < len(rows) {
				return m.openDetailID(rows[m.cursor].KeyID)
			}
		case screenAudit:
			rows := m.visibleAudits()
			if m.cursor < len(rows) {
				return m.openDetailID(rows[m.cursor].Target)
			}
		}
		return m, nil
	case "d":
		if m.screen == screenKeys {
			return m.beginStatus("disable")
		}
	case "e":
		if m.screen == screenKeys {
			return m.beginStatus("enable")
		}
	case "x":
		if m.screen == screenKeys {
			return m.openRevoke(), nil
		}
	case "r":
		if m.screen == screenKeys {
			return m.openRotate(), nil
		}
	case "p":
		if m.screen == screenKeys {
			return m.openPolicy()
		}
	case "a":
		return m.openUpstream()
	case "c":
		m.credUp = 0
		return m.openCredential()
	case "n":
		if m.screen == screenKeys || m.screen == screenSetup {
			m.createCred = 0
			if len(m.creds) == 0 {
				m.credUp = 0
				return m.openCredential()
			}
			return m.openCreate()
		}
	}
	return m, nil
}

func (m model) onDetail(msg tea.KeyMsg) (model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.overlay = overlayNone
		m.scroll = 0
		return m, nil
	case "j", "down":
		m.scroll = min(m.scroll+1, m.maxScroll(m.renderDetail()))
		return m, nil
	case "k", "up":
		if m.scroll > 0 {
			m.scroll--
		}
		return m, nil
	case "d":
		return m.beginStatus("disable")
	case "e":
		return m.beginStatus("enable")
	case "x":
		return m.openRevoke(), nil
	case "r":
		return m.openRotate(), nil
	case "p":
		return m.openPolicy()
	case "n":
		return m.openClient()
	case "?":
		m.helpFrom = overlayDetail
		m.overlay = overlayHelp
		return m, nil
	default:
		return m, nil
	}
}

func (m model) openClient() (model, tea.Cmd) {
	if !m.detailLoaded {
		m.errMsg = "still loading"
		return m, nil
	}
	if len(m.clientRows()) == 0 {
		m.errMsg = "no clients on this key yet"
		return m, nil
	}
	m.clientCursor = 0
	m.clientEditing = false
	m.clientInput.Blur()
	m.overlay = overlayClient
	m.scroll = 0
	m.errMsg = ""
	return m, nil
}

func (m model) onClient(msg tea.KeyMsg) (model, tea.Cmd) {
	rows := m.clientRows()
	if m.clientEditing {
		switch msg.String() {
		case "esc":
			m.clientEditing = false
			m.clientInput.Blur()
			return m, nil
		case "enter":
			return m.saveClientName()
		default:
			var cmd tea.Cmd
			m.clientInput, cmd = m.clientInput.Update(msg)
			return m, cmd
		}
	}
	switch msg.String() {
	case "esc":
		m.overlay = overlayDetail
		m.scroll = 0
		return m, nil
	case "j", "down":
		if m.clientCursor < len(rows)-1 {
			m.clientCursor++
		}
	case "k", "up":
		if m.clientCursor > 0 {
			m.clientCursor--
		}
	case "enter":
		if m.clientCursor < 0 || m.clientCursor >= len(rows) {
			return m, nil
		}
		m.clientInput.SetValue(rows[m.clientCursor].Name)
		m.clientEditing = true
		return m, m.clientInput.Focus()
	}
	return m, nil
}

func (m model) saveClientName() (model, tea.Cmd) {
	rows := m.clientRows()
	if m.clientCursor < 0 || m.clientCursor >= len(rows) {
		return m, nil
	}
	ip := rows[m.clientCursor].IP
	name := strings.TrimSpace(m.clientInput.Value())
	api, ctx := m.api, m.ctx
	m.loading = true
	m.errMsg = ""
	return m, func() tea.Msg {
		err := api.SetClientName(ctx, ip, name)
		return clientNamed{ip: ip, name: name, err: err}
	}
}

func (m model) applyClientName(ip, name string) {
	for i := range m.detailUsage.Clients {
		if m.detailUsage.Clients[i].IP == ip {
			m.detailUsage.Clients[i].Name = name
		}
	}
	for i := range m.detailUsage.Recent {
		if m.detailUsage.Recent[i].IP == ip {
			m.detailUsage.Recent[i].ClientName = name
		}
	}
}

func (m model) onRevoke(msg tea.KeyMsg) (model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.overlay = overlayNone
		m.revokeInput.SetValue("")
		m.revokeInput.Blur()
		return m, nil
	case "enter":
		return m.submitRevoke()
	default:
		var cmd tea.Cmd
		m.revokeInput, cmd = m.revokeInput.Update(msg)
		return m, cmd
	}
}

// rotateGraces are the choices for how long a replaced key keeps working.
// The last one is the incident response: revoke the old key now.
var rotateGraces = []struct {
	label string
	d     time.Duration
}{
	{"24 hours", 24 * time.Hour},
	{"1 hour", time.Hour},
	{"7 days", 7 * 24 * time.Hour},
	{"none, revoke it now", 0},
}

func (m model) onRotate(s string) (model, tea.Cmd) {
	switch s {
	case "esc":
		m.overlay = overlayNone
		return m, nil
	case "left":
		m.rotateGrace = (m.rotateGrace + len(rotateGraces) - 1) % len(rotateGraces)
	case "right":
		m.rotateGrace = (m.rotateGrace + 1) % len(rotateGraces)
	case "enter":
		id, grace := m.rotateID, rotateGraces[m.rotateGrace].d
		api, ctx := m.api, m.ctx
		m.errMsg = ""
		m.loading = true
		return m, func() tea.Msg {
			rot, err := api.RotateKey(ctx, id, grace)
			note := ""
			switch {
			case rot.OldRevoked:
				note = "The old key is revoked, renamed " + rot.OldName + "."
			case rot.OldUntil != nil:
				note = "The old key, renamed " + rot.OldName + ", works until " + fmtTime(*rot.OldUntil) + ". Move the app to this key before then."
			}
			return createdDone{key: rot.Key, note: note, err: err}
		}
	}
	return m, nil
}

func (m model) onConfirm(s string) (model, tea.Cmd) {
	switch s {
	case "esc":
		m.overlay = overlayPolicy
		m.policyConfirm = false
		return m, nil
	case "enter":
		m.policyConfirm = true
		return m.submitPolicy()
	default:
		return m, nil
	}
}

func (m model) onPolicy(msg tea.KeyMsg) (model, tea.Cmd) {
	s := msg.String()
	switch s {
	case "esc":
		m.overlay = overlayNone
		return m, nil
	case "enter":
		if m.polField < policyFields-1 {
			m.polField++
			return m.focusPolicy()
		}
		return m.submitPolicy()
	case "tab", "down":
		m.polField = (m.polField + 1) % policyFields
		return m.focusPolicy()
	case "shift+tab", "up":
		m.polField = (m.polField + policyFields - 1) % policyFields
		return m.focusPolicy()
	case "left":
		if m.polField == 0 {
			m.polMode = (m.polMode + len(policyModes) - 1) % len(policyModes)
			return m, nil
		}
	case "right":
		if m.polField == 0 {
			m.polMode = (m.polMode + 1) % len(policyModes)
			return m, nil
		}
	}
	if m.polField == 0 {
		return m, nil
	}
	return m.editPolicy(msg)
}

func (m model) onCreate(msg tea.KeyMsg) (model, tea.Cmd) {
	s := msg.String()
	switch s {
	case "esc":
		m.overlay = overlayNone
		m.nameInput.Blur()
		return m, nil
	case "enter":
		if m.createField < 2 {
			m.createField++
			return m.focusCreate()
		}
		return m.submitCreate()
	case "tab", "down":
		m.createField = (m.createField + 1) % 3
		return m.focusCreate()
	case "up", "shift+tab":
		m.createField = (m.createField + 2) % 3
		return m.focusCreate()
	case "left":
		if m.createField != 0 {
			m.cycleCreate(-1)
			return m, nil
		}
	case "right":
		if m.createField != 0 {
			m.cycleCreate(1)
			return m, nil
		}
	}
	if m.createField != 0 {
		return m, nil
	}
	var cmd tea.Cmd
	m.nameInput, cmd = m.nameInput.Update(msg)
	return m, cmd
}

func (m model) onUpstream(msg tea.KeyMsg) (model, tea.Cmd) {
	s := msg.String()
	switch s {
	case "esc":
		m.overlay = overlayNone
		m.blurUpstream()
		return m, nil
	case "enter":
		if m.upField < 5 {
			m.upField++
			return m.focusUpstream()
		}
		return m.submitUpstream()
	case "tab", "down":
		m.upField = (m.upField + 1) % 6
		return m.focusUpstream()
	case "up", "shift+tab":
		m.upField = (m.upField + 5) % 6
		return m.focusUpstream()
	case "left", "right":
		if m.upField == 1 || m.upField == 4 {
			m.cycleUpstream(s == "right")
			return m, nil
		}
	}
	return m.editUpstream(msg)
}

func (m model) onCredential(msg tea.KeyMsg) (model, tea.Cmd) {
	s := msg.String()
	switch s {
	case "esc":
		m.credSecret.SetValue("")
		m.overlay = overlayNone
		m.blurCredential()
		return m, nil
	case "enter":
		if m.credField < 3 {
			m.credField++
			return m.focusCredential()
		}
		return m.submitCredential()
	case "tab", "down":
		m.credField = (m.credField + 1) % 4
		return m.focusCredential()
	case "up", "shift+tab":
		m.credField = (m.credField + 3) % 4
		return m.focusCredential()
	case "left", "right":
		if m.credField == 1 || m.credField == 2 {
			m.cycleCredential(s == "right")
			return m, nil
		}
	}
	return m.editCredential(msg)
}

func (m model) onAdmin(msg tea.KeyMsg) (model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.adminInput.SetValue("")
		m.applyToken("")
		m.adminHeld = false
		return m, tea.Quit
	case "enter":
		return m.submitAdmin()
	}
	var cmd tea.Cmd
	m.adminInput, cmd = m.adminInput.Update(msg)
	return m, cmd
}

func (m model) submitAdmin() (model, tea.Cmd) {
	typed := strings.TrimSpace(m.adminInput.Value())
	if typed != "" {
		m.applyToken(typed)
		m.adminInput.SetValue("")
		m.adminHeld = true
	} else if !m.adminHeld {
		m.errMsg = "admin token is required"
		return m, nil
	}
	m.errMsg = ""
	api, ctx := m.api, m.ctx
	return m, func() tea.Msg {
		keys, err := api.ListKeys(ctx)
		return adminReady{keys: keys, err: err}
	}
}

func (m model) applyToken(token string) {
	if m.setToken != nil {
		m.setToken(token)
	}
}

func (m model) focusAdmin() (model, tea.Cmd) {
	return m, m.adminInput.Focus()
}

func (m model) openUpstream() (model, tea.Cmd) {
	m.overlay = overlayUpstream
	m.upField = 0
	m.upProfile = 0
	m.applyPreset(upstreamChoices[0])
	m.errMsg = ""
	m.note = ""
	return m.focusUpstream()
}

func (m model) openCredential() (model, tea.Cmd) {
	if len(m.ups) == 0 {
		return m.openUpstream()
	}
	if m.credUp < 0 || m.credUp >= len(m.ups) {
		m.credUp = len(m.ups) - 1
	}
	envName := credentialEnv(m.ups[m.credUp])
	m.overlay = overlayCredential
	m.credField = 0
	m.credName.SetValue("primary")
	m.credEnv.SetValue(envName)
	m.credSecret.SetValue("")
	if m.lookupEnv(envName) != "" {
		m.credMode = 0
	} else {
		m.credMode = 1
	}
	m.errMsg = ""
	m.note = ""
	return m.focusCredential()
}

func (m model) submitUpstream() (model, tea.Cmd) {
	name := strings.TrimSpace(m.upName.Value())
	host := strings.TrimSpace(m.upHost.Value())
	port, err := strconv.Atoi(strings.TrimSpace(m.upPort.Value()))
	if name == "" || host == "" || err != nil || port < 1 || port > 65535 {
		m.errMsg = "name, host, and a port from 1 to 65535 are required"
		return m, nil
	}
	choice := upstreamChoices[m.upProfile]
	paths := splitPaths(m.upPaths.Value())
	if choice.preset == "" && choice.profile == "generic" && len(paths) == 0 {
		m.errMsg = "a generic upstream needs at least one path"
		return m, nil
	}
	draft := UpstreamDraft{Name: name, Profile: choice.profile, Preset: choice.preset, Host: host, Port: port, TLS: m.upTLS, Paths: paths}
	api := m.api
	ctx := m.ctx
	m.errMsg = ""
	return m, func() tea.Msg {
		up, callErr := api.AddUpstream(ctx, draft)
		return upstreamDone{up: up, err: callErr}
	}
}

func (m model) submitCredential() (model, tea.Cmd) {
	if len(m.ups) == 0 || m.credUp < 0 || m.credUp >= len(m.ups) {
		m.errMsg = "add an upstream first"
		return m, nil
	}
	name := strings.TrimSpace(m.credName.Value())
	if name == "" {
		m.errMsg = "name is required"
		return m, nil
	}
	var secret string
	if m.credMode == 0 {
		envName := strings.TrimSpace(m.credEnv.Value())
		if envName == "" {
			m.errMsg = "environment variable name is required"
			return m, nil
		}
		secret = m.lookupEnv(envName)
		if secret == "" {
			m.errMsg = envName + " is empty in this shell. Type the secret, or export it before starting keman."
			return m, nil
		}
	} else if strings.TrimSpace(m.credSecret.Value()) == "" {
		m.errMsg = "api key is required"
		return m, nil
	} else {
		secret = m.credSecret.Value()
	}
	draft := CredentialDraft{UpstreamID: m.ups[m.credUp].ID, Name: name, Secret: secret}
	api := m.api
	ctx := m.ctx
	m.errMsg = ""
	return m, func() tea.Msg {
		cred, callErr := api.AddCredential(ctx, draft)
		return credentialDone{cred: cred, err: callErr}
	}
}

func (m model) lookupEnv(name string) string {
	if m.getenv == nil {
		return ""
	}
	return m.getenv(name)
}

func splitPaths(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (m *model) cycleUpstream(next bool) {
	if m.upField == 1 {
		prev := upstreamChoices[m.upProfile]
		n := len(upstreamChoices)
		if next {
			m.upProfile = (m.upProfile + 1) % n
		} else {
			m.upProfile = (m.upProfile + n - 1) % n
		}
		if m.upstreamIs(prev) {
			m.applyPreset(upstreamChoices[m.upProfile])
		}
	}
	if m.upField == 4 {
		m.upTLS = !m.upTLS
	}
}

func (m *model) cycleCredential(next bool) {
	if m.credField == 1 && len(m.ups) > 0 {
		n := len(m.ups)
		prevEnv := credentialEnv(m.ups[m.credUp])
		if next {
			m.credUp = (m.credUp + 1) % n
		} else {
			m.credUp = (m.credUp + n - 1) % n
		}
		if m.credEnv.Value() == prevEnv {
			m.credEnv.SetValue(credentialEnv(m.ups[m.credUp]))
		}
	}
	if m.credField == 2 {
		if m.credMode == 0 {
			m.credMode = 1
		} else {
			m.credMode = 0
		}
		m.credSecret.SetValue("")
	}
}

func (m *model) blurUpstream() {
	m.upName.Blur()
	m.upHost.Blur()
	m.upPort.Blur()
	m.upPaths.Blur()
}

func (m *model) blurCredential() {
	m.credName.Blur()
	m.credEnv.Blur()
	m.credSecret.Blur()
}

func (m model) focusUpstream() (model, tea.Cmd) {
	m.blurUpstream()
	switch m.upField {
	case 0:
		return m, m.upName.Focus()
	case 2:
		return m, m.upHost.Focus()
	case 3:
		return m, m.upPort.Focus()
	case 5:
		return m, m.upPaths.Focus()
	default:
		return m, nil
	}
}

func (m model) focusCredential() (model, tea.Cmd) {
	m.blurCredential()
	switch m.credField {
	case 0:
		return m, m.credName.Focus()
	case 3:
		if m.credMode == 0 {
			return m, m.credEnv.Focus()
		}
		return m, m.credSecret.Focus()
	default:
		return m, nil
	}
}

func (m model) editUpstream(msg tea.Msg) (model, tea.Cmd) {
	var cmd tea.Cmd
	switch m.upField {
	case 0:
		m.upName, cmd = m.upName.Update(msg)
	case 2:
		m.upHost, cmd = m.upHost.Update(msg)
	case 3:
		m.upPort, cmd = m.upPort.Update(msg)
	case 5:
		m.upPaths, cmd = m.upPaths.Update(msg)
	}
	return m, cmd
}

func (m model) editCredential(msg tea.Msg) (model, tea.Cmd) {
	var cmd tea.Cmd
	switch m.credField {
	case 0:
		m.credName, cmd = m.credName.Update(msg)
	case 3:
		if m.credMode == 0 {
			m.credEnv, cmd = m.credEnv.Update(msg)
		} else {
			m.credSecret, cmd = m.credSecret.Update(msg)
		}
	}
	return m, cmd
}

func (m model) switchScreen(s screen) (model, tea.Cmd) {
	m.screen = s
	m.overlay = overlayNone
	m.cursor = 0
	m.scroll = 0
	m.loading = true
	m.gen++
	return m, m.fetchCurrent()
}

func (m model) move(d int) model {
	m.cursor += d
	m.clamp()
	return m
}

func (m *model) clamp() {
	n := m.listLen()
	if n == 0 {
		m.cursor = 0
		return
	}
	if m.cursor >= n {
		m.cursor = n - 1
	}
	if m.cursor < 0 {
		m.cursor = 0
	}
}

func (m model) listLen() int {
	switch m.screen {
	case screenKeys:
		return len(m.visibleKeys())
	case screenDetections:
		return len(m.visibleDets())
	case screenAudit:
		return len(m.visibleAudits())
	default:
		return 0
	}
}

func (m model) openDetail() (model, tea.Cmd) {
	k, ok := m.selected()
	if !ok {
		m.errMsg = "no key selected"
		return m, nil
	}
	return m.openDetailID(k.ID)
}

// openDetailID opens the key detail for id, from any list that names a key.
func (m model) openDetailID(id string) (model, tea.Cmd) {
	k, ok := m.keyByID(id)
	if !ok {
		m.errMsg = "this entry is not a listed virtual key"
		return m, nil
	}
	m.detailID = k.ID
	m.detailDets = nil
	m.detailUsage = KeyUsage{}
	m.detailLoaded = false
	m.scroll = 0
	m.overlay = overlayDetail
	return m, tea.Batch(m.fetchDetections(k.ID), m.fetchUsage(k.ID))
}

func (m model) openRevoke() model {
	k, ok := m.currentKey()
	if !ok {
		m.errMsg = "no key selected"
		return m
	}
	if k.Status == kmodel.StatusRevoked {
		m.errMsg = "this key is already revoked"
		return m
	}
	m.revokeID = k.ID
	m.revokeExpect = k.Name
	if m.revokeExpect == "" {
		m.revokeExpect = k.ID
	}
	m.revokeInput.SetValue("")
	m.revokeInput.Focus()
	m.overlay = overlayRevoke
	m.errMsg = ""
	return m
}

func (m model) openRotate() model {
	k, ok := m.currentKey()
	if !ok {
		m.errMsg = "no key selected"
		return m
	}
	if k.Status == kmodel.StatusRevoked {
		m.errMsg = "a revoked key cannot be rotated"
		return m
	}
	m.rotateID = k.ID
	m.rotateName = displayName(k)
	m.rotateGrace = 0
	m.overlay = overlayRotate
	m.errMsg = ""
	return m
}

func (m model) openPolicy() (model, tea.Cmd) {
	k, ok := m.currentKey()
	if !ok {
		m.errMsg = "no key selected"
		return m, nil
	}
	m.policyID = k.ID
	m.policyName = displayName(k)
	m.polMode = 0
	m.polField = 0
	m.policyConfirm = false
	m.policyKeep = Policy{}
	m.rpmInput.SetValue("")
	m.dailyInput.SetValue("")
	m.monthlyInput.SetValue("")
	m.cidrInput.SetValue("")
	m.countryInput.SetValue("")
	m.expiresWas = ""
	if k.ExpiresAt != nil {
		m.expiresWas = k.ExpiresAt.UTC().Format(time.RFC3339)
	}
	m.expiresInput.SetValue(m.expiresWas)
	if k.Policy != nil {
		m.cidrInput.SetValue(strings.Join(k.Policy.CIDRs, ", "))
		m.countryInput.SetValue(strings.Join(k.Policy.Countries, ", "))
		m.polMode = modeIndex(k.Policy.Mode)
		m.policyKeep = *k.Policy
		if k.Policy.RPM != nil {
			m.rpmInput.SetValue(strconv.Itoa(*k.Policy.RPM))
		}
		if k.Policy.DailyCapMicro != nil {
			m.dailyInput.SetValue(money.FormatUSD(*k.Policy.DailyCapMicro))
		}
		if k.Policy.MonthlyCapMicro != nil {
			m.monthlyInput.SetValue(money.FormatUSD(*k.Policy.MonthlyCapMicro))
		}
	}
	m.overlay = overlayPolicy
	m.errMsg = ""
	return m.focusPolicy()
}

func (m model) openCreate() (model, tea.Cmd) {
	m.createField = 0
	m.createKind = 0
	if m.createCred < 0 || m.createCred >= len(m.creds) {
		m.createCred = 0
	}
	m.nameInput.SetValue("")
	m.overlay = overlayCreate
	m.errMsg = ""
	m.note = ""
	next, cmd := m.focusCreate()
	if len(m.creds) == 0 {
		return next, tea.Batch(cmd, next.fetchCreds())
	}
	return next, cmd
}

func (m model) beginStatus(action string) (model, tea.Cmd) {
	k, ok := m.currentKey()
	if !ok {
		m.errMsg = "no key selected"
		return m, nil
	}
	if k.Status == kmodel.StatusRevoked {
		m.errMsg = "a revoked key stays revoked"
		return m, nil
	}
	id := k.ID
	name := displayName(k)
	api := m.api
	ctx := m.ctx
	m.errMsg = ""
	return m, func() tea.Msg {
		err := api.SetStatus(ctx, id, action)
		return actionDone{action: action, name: name, err: err}
	}
}

func (m model) submitRevoke() (model, tea.Cmd) {
	typed := strings.TrimSpace(m.revokeInput.Value())
	if typed != m.revokeExpect {
		m.errMsg = "type " + m.revokeExpect + " to revoke"
		return m, nil
	}
	id := m.revokeID
	name := m.revokeExpect
	api := m.api
	ctx := m.ctx
	m.errMsg = ""
	return m, func() tea.Msg {
		err := api.SetStatus(ctx, id, "revoke")
		return actionDone{action: "revoke", name: name, err: err}
	}
}

var policyModes = []string{kmodel.ModeAlertOnly, kmodel.ModeDryRun, kmodel.ModeAutoDisable}

func modeIndex(mode string) int {
	for i, name := range policyModes {
		if name == mode {
			return i
		}
	}
	return 0
}

func (m model) submitPolicy() (model, tea.Cmd) {
	p, err := m.builtPolicy()
	if err != nil {
		m.errMsg = err.Error()
		return m, nil
	}
	exp, expChanged, err := m.builtExpiry(time.Now())
	if err != nil {
		m.errMsg = "expires: " + err.Error()
		return m, nil
	}
	id := m.policyID
	confirm := m.policyConfirm
	api := m.api
	ctx := m.ctx
	m.errMsg = ""
	m.loading = true
	return m, func() tea.Msg {
		_, err := api.PutPolicy(ctx, id, p, confirm)
		if err == nil && expChanged {
			err = api.SetExpiry(ctx, id, exp)
		}
		return policyDone{err: err}
	}
}

// builtExpiry reads the expires field. changed is false when the field
// still shows the key's current expiry, so an expired key is left alone.
func (m model) builtExpiry(now time.Time) (at *time.Time, changed bool, err error) {
	text := strings.TrimSpace(m.expiresInput.Value())
	if text == m.expiresWas {
		return nil, false, nil
	}
	if text == "" {
		return nil, true, nil
	}
	at, err = expiry.Parse(text, now)
	return at, err == nil, err
}

func (m model) builtPolicy() (Policy, error) {
	p := m.policyKeep
	p.Mode = policyModes[m.polMode]
	rpm := strings.TrimSpace(m.rpmInput.Value())
	if rpm == "" {
		p.RPM = nil
	} else {
		n, err := strconv.Atoi(rpm)
		if err != nil || n <= 0 {
			return Policy{}, fmt.Errorf("rpm must be a positive integer")
		}
		p.RPM = &n
	}
	daily, err := parseUSD(m.dailyInput.Value())
	if err != nil {
		return Policy{}, fmt.Errorf("daily cap: %s", err.Error())
	}
	monthly, err := parseUSD(m.monthlyInput.Value())
	if err != nil {
		return Policy{}, fmt.Errorf("monthly cap: %s", err.Error())
	}
	p.DailyCapMicro = daily
	p.MonthlyCapMicro = monthly
	p.CIDRs = splitList(m.cidrInput.Value())
	p.Countries = nil
	for _, c := range splitList(m.countryInput.Value()) {
		p.Countries = append(p.Countries, strings.ToUpper(c))
	}
	return p, nil
}

// splitList reads a list separated by commas or spaces.
func splitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
}

func parseUSD(s string) (*int64, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "$")
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	v, err := money.ParseUSD(s)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func (m model) submitCreate() (model, tea.Cmd) {
	name := strings.TrimSpace(m.nameInput.Value())
	if name == "" {
		m.errMsg = "name is required"
		return m, nil
	}
	if len(m.creds) == 0 || m.createCred < 0 || m.createCred >= len(m.creds) {
		m.errMsg = "press c to add a credential"
		return m, nil
	}
	cred := m.creds[m.createCred]
	kind := kmodel.KindStandard
	if m.createKind == 1 {
		kind = kmodel.KindCanary
	}
	api := m.api
	ctx := m.ctx
	m.errMsg = ""
	m.loading = true
	return m, func() tea.Msg {
		key, err := api.CreateKey(ctx, cred.ID, name, kind)
		return createdDone{key: key, err: err}
	}
}

func (m *model) cycleCreate(d int) {
	if m.createField == 1 && len(m.creds) > 0 {
		n := len(m.creds)
		m.createCred = (m.createCred + d + n) % n
	}
	if m.createField == 2 {
		m.createKind = (m.createKind + 1) % 2
	}
}

// policyFields is the policy form, in order: mode, then who may use the
// key (addresses, countries, expiry), then the rate limit and spend caps.
const policyFields = 7

func (m *model) policyInput(field int) *textinput.Model {
	switch field {
	case 1:
		return &m.cidrInput
	case 2:
		return &m.countryInput
	case 3:
		return &m.expiresInput
	case 4:
		return &m.rpmInput
	case 5:
		return &m.dailyInput
	case 6:
		return &m.monthlyInput
	}
	return nil
}

func (m model) focusPolicy() (model, tea.Cmd) {
	for f := 1; f < policyFields; f++ {
		m.policyInput(f).Blur()
	}
	if in := m.policyInput(m.polField); in != nil {
		return m, in.Focus()
	}
	return m, nil
}

func (m model) focusCreate() (model, tea.Cmd) {
	m.nameInput.Blur()
	if m.createField == 0 {
		return m, m.nameInput.Focus()
	}
	return m, nil
}

func (m model) editPolicy(msg tea.Msg) (model, tea.Cmd) {
	in := m.policyInput(m.polField)
	if in == nil {
		return m, nil
	}
	var cmd tea.Cmd
	*in, cmd = in.Update(msg)
	return m, cmd
}

// pollErr shows a failed background load. The next good load clears it.
func (m *model) pollErr(err error) {
	m.errMsg = errText(err)
	m.errFromPoll = true
}

func (m *model) clearPollErr() {
	if m.errFromPoll {
		m.errMsg = ""
		m.errFromPoll = false
	}
}

func (m model) filter() string {
	return m.filters[m.screen]
}

func (m model) hasData() bool {
	if m.overlay != overlayNone {
		return true
	}
	return m.loaded[m.screen]
}

// textFocused reports whether keys are being typed into a field, so q is
// text rather than quit.
func (m model) textFocused() bool {
	if m.filtering {
		return true
	}
	switch m.overlay {
	case overlayRevoke, overlayAdmin:
		return true
	case overlayClient:
		return m.clientEditing
	case overlayPolicy:
		return m.polField > 0
	case overlayCreate:
		return m.createField == 0
	case overlayUpstream:
		return m.upField != 1 && m.upField != 4
	case overlayCredential:
		return m.credField == 0 || m.credField == 3
	}
	return false
}

// onLastField reports whether enter saves the open form.
func (m model) onLastField() bool {
	switch m.overlay {
	case overlayPolicy:
		return m.polField == policyFields-1
	case overlayCreate:
		return m.createField == 2
	case overlayUpstream:
		return m.upField == 5
	case overlayCredential:
		return m.credField == 3
	}
	return false
}

// maxScroll is the furthest scroll that still fills the body with text.
func (m model) maxScroll(text string) int {
	n := lineCount(strings.TrimSuffix(text, "\n"))
	budget := m.bodyBudget()
	if budget <= 0 {
		return max(0, n-1)
	}
	return max(0, n-budget)
}

// keyLabel names a key id by its name when the key is listed.
func (m model) keyLabel(id string) string {
	if k, ok := m.keyByID(id); ok && k.Name != "" {
		return k.Name + " (" + id + ")"
	}
	return id
}

func (m model) upstreamName(id string) string {
	for _, u := range m.ups {
		if u.ID == id && u.Name != "" {
			return u.Name
		}
	}
	return id
}

func (m model) fetchCurrent() tea.Cmd {
	if m.overlay == overlayDetail {
		return tea.Batch(m.fetchKeys(), m.fetchDetections(m.detailID), m.fetchUsage(m.detailID))
	}
	switch m.screen {
	case screenDetections:
		return m.fetchDetections("")
	case screenAudit:
		return m.fetchAudit()
	case screenSetup:
		return m.fetchSetup()
	default:
		return m.fetchKeys()
	}
}

func (m model) fetchKeys() tea.Cmd {
	api, ctx, gen := m.api, m.ctx, m.gen
	return func() tea.Msg {
		keys, err := api.ListKeys(ctx)
		return keysLoaded{gen: gen, keys: keys, err: err}
	}
}

type usageLoaded struct {
	keyID string
	usage KeyUsage
	err   error
}

type clientNamed struct {
	ip, name string
	err      error
}

func (m model) fetchUsage(keyID string) tea.Cmd {
	api, ctx := m.api, m.ctx
	return func() tea.Msg {
		usage, err := api.KeyUsage(ctx, keyID)
		return usageLoaded{keyID: keyID, usage: usage, err: err}
	}
}

func (m model) fetchDetections(keyID string) tea.Cmd {
	api, ctx, gen := m.api, m.ctx, m.gen
	return func() tea.Msg {
		rows, err := api.ListDetections(ctx, keyID)
		return detsLoaded{gen: gen, keyID: keyID, rows: rows, err: err}
	}
}

func (m model) fetchAudit() tea.Cmd {
	api, ctx, gen := m.api, m.ctx, m.gen
	return func() tea.Msg {
		rows, err := api.ListAudit(ctx)
		return auditLoaded{gen: gen, rows: rows, err: err}
	}
}

func (m model) fetchSetup() tea.Cmd {
	api, ctx, gen := m.api, m.ctx, m.gen
	return func() tea.Msg {
		ups, err1 := api.ListUpstreams(ctx)
		creds, err2 := api.ListCredentials(ctx)
		alerts, err3 := api.ListAlerts(ctx)
		err := err1
		if err == nil {
			err = err2
		}
		if err == nil {
			err = err3
		}
		return setupLoaded{gen: gen, ups: ups, creds: creds, alerts: alerts, err: err}
	}
}

type credsLoaded struct {
	creds []Credential
	err   error
}

func (m model) fetchCreds() tea.Cmd {
	api, ctx := m.api, m.ctx
	return func() tea.Msg {
		creds, err := api.ListCredentials(ctx)
		return credsLoaded{creds: creds, err: err}
	}
}

func (m model) currentKey() (Key, bool) {
	switch m.overlay {
	case overlayDetail:
		return m.keyByID(m.detailID)
	case overlayRevoke:
		return m.keyByID(m.revokeID)
	case overlayRotate:
		return m.keyByID(m.rotateID)
	case overlayPolicy, overlayConfirm:
		return m.keyByID(m.policyID)
	default:
		return m.selected()
	}
}

func (m model) selected() (Key, bool) {
	rows := m.visibleKeys()
	if m.cursor < 0 || m.cursor >= len(rows) {
		return Key{}, false
	}
	return rows[m.cursor], true
}

func (m model) keyByID(id string) (Key, bool) {
	for _, k := range m.keys {
		if k.ID == id {
			return k, true
		}
	}
	return Key{}, false
}

func (m model) visibleKeys() []Key {
	return filterBy(m.keys, m.filters[screenKeys], func(k Key) string {
		return k.Name + " " + k.ID
	})
}

func (m model) visibleDets() []Detection {
	return groupDetections(filterBy(m.dets, m.filters[screenDetections], func(d Detection) string {
		return d.Rule + " " + d.KeyID + " " + d.Severity
	}))
}

// detectionGroupWindow matches the engine's incident window: a rule that
// fires again on the same key within an hour is the same incident.
const detectionGroupWindow = time.Hour

// groupDetections folds detections of one rule on one key that fire within
// detectionGroupWindow of each other into one row with a count, so a burst
// of abusive requests reads as one incident. Rows keep the position of
// their first detection and show the latest time.
func groupDetections(ds []Detection) []Detection {
	type groupKey struct{ key, rule, sev string }
	out := make([]Detection, 0, len(ds))
	open := map[groupKey]int{}
	span := map[groupKey][2]time.Time{}
	for _, d := range ds {
		k := groupKey{d.KeyID, d.Rule, d.Severity}
		n := d.Count
		if n < 1 {
			n = 1
		}
		if i, ok := open[k]; ok {
			sp := span[k]
			if !d.Time.Before(sp[0].Add(-detectionGroupWindow)) && !d.Time.After(sp[1].Add(detectionGroupWindow)) {
				out[i].Count += n
				if d.Time.After(out[i].Time) {
					out[i].Time = d.Time
				}
				if d.Time.Before(sp[0]) {
					sp[0] = d.Time
				}
				if d.Time.After(sp[1]) {
					sp[1] = d.Time
				}
				span[k] = sp
				continue
			}
		}
		d.Count = n
		open[k] = len(out)
		span[k] = [2]time.Time{d.Time, d.Time}
		out = append(out, d)
	}
	return out
}

func (m model) visibleAudits() []AuditRow {
	return filterBy(m.audits, m.filters[screenAudit], func(a AuditRow) string {
		return a.Action + " " + a.Target + " " + a.Actor
	})
}

func filterBy[T any](rows []T, q string, text func(T) string) []T {
	q = strings.ToLower(strings.TrimSpace(q))
	if q == "" {
		return rows
	}
	out := make([]T, 0, len(rows))
	for _, row := range rows {
		if strings.Contains(strings.ToLower(text(row)), q) {
			out = append(out, row)
		}
	}
	return out
}

func displayName(k Key) string {
	if k.Name != "" {
		return k.Name
	}
	return k.ID
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
