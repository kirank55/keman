package tui

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	kmodel "github.com/kirank55/keman/internal/model"
	"github.com/kirank55/keman/internal/money"
)

var (
	dimStyle  = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "242", Dark: "245"})
	okStyle   = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "28", Dark: "42"})
	warnStyle = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "172", Dark: "214"})
	badStyle  = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "160", Dark: "203"})
	selStyle  = lipgloss.NewStyle().
			Foreground(lipgloss.AdaptiveColor{Light: "231", Dark: "231"}).
			Background(lipgloss.AdaptiveColor{Light: "33", Dark: "33"})
	tabStyle  = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "27", Dark: "75"}).Underline(true)
	errStyle  = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "160", Dark: "203"})
	noteStyle = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "28", Dark: "42"})
)

const helpText = `keman

1 keys    2 detections    3 audit    4 setup
tab switches view

j k or arrows move
enter opens a key
d disable    e enable
x revoke     type the key name
p policy     dollars, not microdollars
a add upstream    OpenRouter is filled in
c add credential  type the secret, or read an environment variable
n new key         the virtual key is shown once
/ filter
? help       q quit

Type the admin token when asked, unless KEMAN_ADMIN_TOKEN is set.
On the credential form, type the provider API key or name an environment variable.
Rekey and admin-token rotate stay on the CLI.
`

func (m model) View() string {
	body := m.renderBody()
	if m.overlay == overlayDetail {
		body = scrollText(body, m.scroll)
	}
	if m.overlay != overlayToken {
		body = clip(body, m.bodyBudget())
	}
	var b strings.Builder
	b.WriteString(m.header())
	b.WriteString("\n")
	b.WriteString(body)
	if !strings.HasSuffix(body, "\n") {
		b.WriteString("\n")
	}
	if m.errMsg != "" {
		b.WriteString(errStyle.Render(fit(m.errMsg, m.lineWidth())))
		b.WriteString("\n")
	}
	b.WriteString(m.footer())
	b.WriteString("\n")
	return b.String()
}

func (m model) renderBody() string {
	switch m.overlay {
	case overlayHelp:
		return helpText
	case overlayToken:
		return m.renderToken()
	case overlayRevoke:
		return m.renderRevoke()
	case overlayConfirm:
		return m.renderConfirm()
	case overlayPolicy:
		return m.renderPolicy()
	case overlayCreate:
		return m.renderCreate()
	case overlayUpstream:
		return m.renderUpstream()
	case overlayCredential:
		return m.renderCredential()
	case overlayAdmin:
		return m.renderAdmin()
	case overlayDetail:
		return m.renderDetail()
	}
	switch m.screen {
	case screenDetections:
		return m.renderDetections()
	case screenAudit:
		return m.renderAudit()
	case screenSetup:
		return m.renderSetup()
	default:
		return m.renderKeys()
	}
}

func (m model) header() string {
	host := m.base
	if host == "" {
		host = "admin API"
	}
	left := dimStyle.Render("keman · " + host)
	labels := []struct {
		name string
		s    screen
	}{
		{"keys", screenKeys},
		{"detections", screenDetections},
		{"audit", screenAudit},
		{"setup", screenSetup},
	}
	parts := make([]string, len(labels))
	for i, label := range labels {
		if label.s == m.screen {
			parts[i] = tabStyle.Render(label.name)
		} else {
			parts[i] = dimStyle.Render(label.name)
		}
	}
	right := strings.Join(parts, "  ")
	gap := m.width - lipgloss.Width(left) - lipgloss.Width(right)
	if m.width == 0 || gap < 2 {
		return left + "  " + right
	}
	return left + strings.Repeat(" ", gap) + right
}

func (m model) footer() string {
	if m.filtering {
		return dimStyle.Render("filter · enter keeps it · esc clears")
	}
	if m.note != "" && m.errMsg == "" {
		return noteStyle.Render(m.note)
	}
	switch m.overlay {
	case overlayToken:
		return dimStyle.Render("enter clears the key from this screen")
	case overlayRevoke:
		return dimStyle.Render("enter revoke · esc cancel")
	case overlayConfirm:
		return dimStyle.Render("enter confirm auto_disable · esc back")
	case overlayPolicy:
		return dimStyle.Render("left/right mode · enter next · esc cancel")
	case overlayCreate, overlayUpstream, overlayCredential:
		return dimStyle.Render("enter next · left/right choice · esc cancel")
	case overlayAdmin:
		return dimStyle.Render("enter continues · esc quits")
	case overlayHelp:
		return dimStyle.Render("esc back")
	case overlayDetail:
		return dimStyle.Render("d disable · e enable · x revoke · p policy · j/k scroll · esc back")
	}
	switch m.screen {
	case screenDetections, screenAudit:
		return dimStyle.Render("a upstream · c credential · j/k move · / filter · 1-4 views · q quit")
	case screenSetup:
		return dimStyle.Render("a upstream · c credential · j/k scroll · 1-4 views · q quit")
	default:
		return dimStyle.Render("a upstream · c credential · n new · d disable · e enable · x revoke · p policy · q quit")
	}
}

func (m model) renderKeys() string {
	rows := m.visibleKeys()
	var b strings.Builder
	b.WriteString(m.filterBanner())
	if len(rows) == 0 {
		if len(m.keys) == 0 {
			b.WriteString("no keys yet\n\n")
			b.WriteString("a  add upstream\n")
			b.WriteString("c  add credential\n")
			b.WriteString("n  new virtual key\n")
		} else {
			b.WriteString("no keys match\n")
		}
		return b.String()
	}
	b.WriteString(dimStyle.Render(m.keyHead()))
	b.WriteString("\n")
	start, end := m.span(len(rows))
	for i := start; i < end; i++ {
		b.WriteString(m.keyLine(rows[i], i == m.cursor))
		b.WriteString("\n")
	}
	return b.String()
}

func (m model) keyHead() string {
	if m.wide() {
		return "  " + fit("name", 16) + "  " + fit("status", 10) + "  " + fit("today", 18) + "  " + fit("cap", 10) + "  " + fit("mode", 14)
	}
	return "  " + fit("name", 16) + "  " + fit("status", 10) + "  " + fit("today", 18)
}

func (m model) keyLine(k Key, selected bool) string {
	label := statusLabel(k)
	today := "$" + money.FormatUSD(k.SpendToday)
	if k.SpendOpen > 0 {
		today += " (+$" + money.FormatUSD(k.SpendOpen) + ")"
	}
	cap := "—"
	mode := "—"
	if k.Kind != kmodel.KindCanary && k.Policy != nil {
		if k.Policy.Mode != "" {
			mode = k.Policy.Mode
		}
		cap = capLine(k.Policy.DailyCapMicro)
	}
	name := fit(displayName(k), 16)
	if selected {
		if m.wide() {
			return selStyle.Render("> " + name + "  " + fit(label, 10) + "  " + fit(today, 18) + "  " + fit(cap, 10) + "  " + fit(mode, 14))
		}
		return selStyle.Render("> " + name + "  " + fit(label, 10) + "  " + fit(today, 18))
	}
	status := statusStyle(k).Render(fit(label, 10))
	if m.wide() {
		return "  " + name + "  " + status + "  " + fit(today, 18) + "  " + fit(cap, 10) + "  " + fit(mode, 14)
	}
	return "  " + name + "  " + status + "  " + fit(today, 18)
}

func (m model) renderDetections() string {
	rows := m.visibleDets()
	var b strings.Builder
	b.WriteString(m.filterBanner())
	if len(rows) == 0 {
		b.WriteString("no detections\n")
		return b.String()
	}
	b.WriteString(dimStyle.Render("  " + fit("time", 12) + "  " + fit("severity", 10) + "  " + fit("rule", 22) + "  key"))
	b.WriteString("\n")
	start, end := m.span(len(rows))
	for i := start; i < end; i++ {
		d := rows[i]
		line := fit(fmtTime(d.Time), 12) + "  " + fit(d.Severity, 10) + "  " + fit(d.Rule, 22) + "  " + d.KeyID
		if i == m.cursor {
			line = selStyle.Render("> " + line)
		} else {
			line = "  " + line
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

func (m model) renderAudit() string {
	rows := m.visibleAudits()
	var b strings.Builder
	b.WriteString(m.filterBanner())
	if len(rows) == 0 {
		b.WriteString("no audit entries\n")
		return b.String()
	}
	b.WriteString(dimStyle.Render("  " + fit("time", 12) + "  " + fit("action", 18) + "  " + fit("target", 14) + "  actor"))
	b.WriteString("\n")
	start, end := m.span(len(rows))
	for i := start; i < end; i++ {
		a := rows[i]
		line := fit(fmtTime(a.Time), 12) + "  " + fit(a.Action, 18) + "  " + fit(a.Target, 14) + "  " + a.Actor
		if i == m.cursor {
			line = selStyle.Render("> " + line)
		} else {
			line = "  " + line
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

func (m model) renderSetup() string {
	var b strings.Builder
	b.WriteString("upstreams\n")
	if len(m.ups) == 0 {
		b.WriteString("  no upstreams\n")
	}
	for _, u := range m.ups {
		tls := "plain"
		if u.TLS {
			tls = "tls"
		}
		fmt.Fprintf(&b, "  %s  %s  %s:%d  %s\n", u.Name, u.Profile, u.Host, u.Port, tls)
	}
	b.WriteString("\ncredentials\n")
	if len(m.creds) == 0 {
		b.WriteString("  no credentials\n")
	}
	for _, c := range m.creds {
		last := c.Last4
		if last == "" {
			last = "—"
		}
		fmt.Fprintf(&b, "  %s  %s  last4 %s\n", c.Name, c.AuthStyle, last)
	}
	b.WriteString("\nalert destinations\n")
	if len(m.alerts) == 0 {
		b.WriteString("  no destinations\n")
	}
	for _, a := range m.alerts {
		fmt.Fprintf(&b, "  %s  %s  %s\n", a.Kind, a.ID, a.URL)
	}
	b.WriteString("\n")
	b.WriteString(dimStyle.Render("a add upstream · c add credential"))
	b.WriteString("\n")
	b.WriteString(dimStyle.Render("rotate, rekey, and alerts stay on the CLI"))
	b.WriteString("\n")
	text := b.String()
	lines := strings.Split(text, "\n")
	scroll := m.scroll
	if scroll >= len(lines) {
		scroll = len(lines) - 1
	}
	if scroll < 0 {
		scroll = 0
	}
	if scroll > 0 {
		lines = lines[scroll:]
	}
	return strings.Join(lines, "\n")
}

func (m model) renderDetail() string {
	k, ok := m.keyByID(m.detailID)
	if !ok {
		return "that key is no longer listed\n"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s   %s   %s   %s\n", displayName(k), k.ID, statusLabel(k), k.Kind)
	fmt.Fprintf(&b, "today %s   month $%s\n", todayLine(k), money.FormatUSD(k.SpendMonth))
	if k.Policy != nil {
		mode := k.Policy.Mode
		if mode == "" {
			mode = kmodel.ModeAlertOnly
		}
		rpm := "unlimited"
		if k.Policy.RPM != nil {
			rpm = strconv.Itoa(*k.Policy.RPM)
		}
		fmt.Fprintf(&b, "%s   rpm %s   daily %s   monthly %s\n", mode, rpm, capLine(k.Policy.DailyCapMicro), capLine(k.Policy.MonthlyCapMicro))
		if len(k.Policy.Models) > 0 {
			fmt.Fprintf(&b, "models %s\n", strings.Join(k.Policy.Models, ", "))
		}
		if len(k.Policy.Paths) > 0 {
			fmt.Fprintf(&b, "paths %s\n", strings.Join(k.Policy.Paths, ", "))
		}
	}
	b.WriteString("\nusage\n")
	if !m.detailLoaded {
		b.WriteString("loading usage…\n")
	} else {
		b.WriteString(renderUsage(m.detailUsage))
	}
	b.WriteString("\ndetections\n")
	if len(m.detailDets) == 0 {
		b.WriteString("none\n")
	}
	for _, d := range m.detailDets {
		fmt.Fprintf(&b, "%s  %s  %s\n", fmtTime(d.Time), d.Severity, d.Rule)
	}
	return b.String()
}

func renderUsage(u KeyUsage) string {
	var b strings.Builder
	if u.Requests == 0 {
		b.WriteString("no requests yet\n")
		return b.String()
	}
	fmt.Fprintf(&b, "%d requests", u.Requests)
	if !u.LastSeen.IsZero() {
		fmt.Fprintf(&b, "   last %s", fmtTime(u.LastSeen))
	}
	b.WriteString("\n")
	fmt.Fprintf(&b, "tokens in %d  out %d", u.TokensIn, u.TokensOut)
	if u.Cached > 0 {
		fmt.Fprintf(&b, "  cached %d", u.Cached)
	}
	if u.CacheWrite > 0 {
		fmt.Fprintf(&b, "  cache write %d", u.CacheWrite)
	}
	b.WriteString("\n")
	if u.Priced == 0 {
		b.WriteString("cost —\n")
	} else {
		fmt.Fprintf(&b, "cost $%s", money.FormatUSD(u.CostMicro))
		if u.Estimated > 0 {
			b.WriteString("  estimated")
		}
		b.WriteString("\n")
	}
	b.WriteString("\nclients\n")
	if len(u.Clients) == 0 {
		b.WriteString("none\n")
	}
	for _, c := range u.Clients {
		fmt.Fprintf(&b, "%s   %d requests   last %s\n", clientWhere(c), c.Requests, fmtTime(c.LastSeen))
	}
	b.WriteString("\nmodels\n")
	if len(u.Models) == 0 {
		b.WriteString("none\n")
	}
	for _, item := range u.Models {
		name := item.Model
		if name == "" {
			name = "—"
		}
		cost := "—"
		if item.Priced > 0 {
			cost = "$" + money.FormatUSD(item.CostMicro)
		}
		fmt.Fprintf(&b, "%s   %d requests   in %d out %d  %s\n", name, item.Requests, item.TokensIn, item.TokensOut, cost)
	}
	b.WriteString("\nrecent requests\n")
	if len(u.Recent) == 0 {
		b.WriteString("none\n")
	}
	for _, r := range u.Recent {
		modelName := r.Model
		if modelName == "" {
			modelName = "—"
		}
		line := fmt.Sprintf("%s  %d  %dms  %s  %s", fmtTime(r.Time), r.Status, r.LatencyMS, r.IP, modelName)
		if r.BlockedCode != "" {
			line += "  " + r.BlockedCode
		}
		b.WriteString(line)
		b.WriteString("\n")
		cost := "—"
		if r.CostMicro != nil {
			cost = "$" + money.FormatUSD(*r.CostMicro)
			if r.CostEstimated {
				cost += " estimated"
			}
		}
		fmt.Fprintf(&b, "  %s   in %d out %d  %s\n", r.Operation, r.TokensIn, r.TokensOut, cost)
	}
	return b.String()
}

func clientWhere(c UsageClient) string {
	s := c.IP
	if c.Country != "" {
		s += " " + c.Country
	}
	if c.ASN != 0 {
		s += fmt.Sprintf(" AS%d", c.ASN)
	}
	return s
}

func (m model) renderPolicy() string {
	var b strings.Builder
	fmt.Fprintf(&b, "policy  %s\n\n", m.policyName)
	b.WriteString(fieldLine(m.polField == 0, "mode", policyModes[m.polMode]))
	b.WriteString(fieldLine(m.polField == 1, "rpm", m.rpmInput.View()))
	b.WriteString(fieldLine(m.polField == 2, "daily $", m.dailyInput.View()))
	b.WriteString(fieldLine(m.polField == 3, "month $", m.monthlyInput.View()))
	b.WriteString("\nAllowlists already on this key are kept.\n")
	return b.String()
}

func (m model) renderUpstream() string {
	profile := "openai"
	if m.upProfile >= 0 && m.upProfile < len(upstreamProfiles) {
		profile = upstreamProfiles[m.upProfile]
	}
	tls := "off"
	if m.upTLS {
		tls = "on"
	}
	var b strings.Builder
	b.WriteString("add upstream\n\n")
	b.WriteString(fieldLine(m.upField == 0, "name", m.upName.View()))
	b.WriteString(fieldLine(m.upField == 1, "profile", profile))
	b.WriteString(fieldLine(m.upField == 2, "host", m.upHost.View()))
	b.WriteString(fieldLine(m.upField == 3, "port", m.upPort.View()))
	b.WriteString(fieldLine(m.upField == 4, "tls", tls))
	b.WriteString(fieldLine(m.upField == 5, "paths", m.upPaths.View()))
	b.WriteString("\n")
	b.WriteString(dimStyle.Render("OpenRouter is filled in. Change the host and paths for another provider."))
	b.WriteString("\n")
	return b.String()
}

func (m model) renderCredential() string {
	upName := "—"
	if m.credUp >= 0 && m.credUp < len(m.ups) {
		upName = m.ups[m.credUp].Name
		if upName == "" {
			upName = m.ups[m.credUp].ID
		}
	}
	from := "type it"
	valueLabel := "api key"
	value := m.credSecret.View()
	if m.credMode == 0 {
		from = "environment"
		valueLabel = "variable"
		value = m.credEnv.View()
	}
	var b strings.Builder
	b.WriteString("add credential\n\n")
	b.WriteString(fieldLine(m.credField == 0, "name", m.credName.View()))
	b.WriteString(fieldLine(m.credField == 1, "upstream", upName))
	b.WriteString(fieldLine(m.credField == 2, "from", from))
	b.WriteString(fieldLine(m.credField == 3, valueLabel, value))
	b.WriteString("\n")
	b.WriteString(dimStyle.Render("Type the provider API key. It is masked and not shown again."))
	b.WriteString("\n")
	return b.String()
}

func (m model) renderAdmin() string {
	var b strings.Builder
	b.WriteString("admin token\n\n")
	b.WriteString(m.adminInput.View())
	b.WriteString("\n\n")
	b.WriteString(dimStyle.Render("From keman init. It is masked and kept only in this process."))
	b.WriteString("\n")
	return b.String()
}

func (m model) renderCreate() string {
	var b strings.Builder
	b.WriteString("new virtual key\n\n")
	b.WriteString(fieldLine(m.createField == 0, "name", m.nameInput.View()))
	cred := "—"
	if len(m.creds) == 0 {
		cred = "no credentials yet"
	} else if m.createCred >= 0 && m.createCred < len(m.creds) {
		c := m.creds[m.createCred]
		cred = c.Name
		if cred == "" {
			cred = c.ID
		}
	}
	kind := "standard"
	if m.createKind == 1 {
		kind = "canary"
	}
	b.WriteString(fieldLine(m.createField == 1, "credential", cred))
	b.WriteString(fieldLine(m.createField == 2, "kind", kind))
	return b.String()
}

func (m model) renderRevoke() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Revoke is permanent. Type %s to revoke this key.\n\n", m.revokeExpect)
	b.WriteString(m.revokeInput.View())
	b.WriteString("\n")
	return b.String()
}

func (m model) renderConfirm() string {
	var b strings.Builder
	name := m.policyName
	if name == "" {
		name = m.policyID
	}
	fmt.Fprintf(&b, "Switch %s to auto_disable.\n\n", name)
	b.WriteString("Dry run, last 7 days\n")
	if m.confirmReport.WouldDisable {
		when := "yes"
		if m.confirmReport.WouldDisableAt != nil {
			when = "yes at " + fmtTime(*m.confirmReport.WouldDisableAt) + " UTC"
		}
		b.WriteString("Would disable: " + when + "\n")
	} else {
		b.WriteString("Would disable: no\n")
	}
	fmt.Fprintf(&b, "Requests that would have been blocked: %d\n", m.confirmReport.RequestsWouldBlock)
	fmt.Fprintf(&b, "Detections: %d\n", m.confirmReport.Detections)
	return b.String()
}

func (m model) renderToken() string {
	var b strings.Builder
	b.WriteString("This virtual key is shown once.\n\n")
	if m.tokenName != "" {
		b.WriteString(m.tokenName)
		b.WriteString("\n")
	}
	b.WriteString(m.token)
	b.WriteString("\n")
	return b.String()
}

func (m model) filterBanner() string {
	if m.filter == "" {
		return ""
	}
	return dimStyle.Render("filter: "+m.filter) + "\n"
}

func (m model) wide() bool {
	return m.width == 0 || m.width >= 80
}

func (m model) lineWidth() int {
	if m.width > 2 {
		return m.width - 2
	}
	return 80
}

func (m model) bodyBudget() int {
	if m.height <= 0 {
		return 0
	}
	n := m.height - 4
	if m.errMsg != "" {
		n--
	}
	if n < 1 {
		return 1
	}
	return n
}

func (m model) span(n int) (int, int) {
	if n == 0 {
		return 0, 0
	}
	budget := m.rowBudget()
	start := 0
	if m.cursor >= budget {
		start = m.cursor - budget + 1
	}
	end := start + budget
	if end > n {
		end = n
	}
	if start > end {
		start = end
	}
	return start, end
}

func (m model) rowBudget() int {
	if m.height <= 0 {
		return 20
	}
	n := m.height - 6
	if n < 3 {
		n = 3
	}
	return n
}

func fieldLine(on bool, label, value string) string {
	mark := "  "
	if on {
		mark = "> "
	}
	return mark + fit(label, 12) + value + "\n"
}

func statusLabel(k Key) string {
	switch k.Status {
	case kmodel.StatusRevoked:
		return "revoked"
	case kmodel.StatusDisabled:
		return "disabled"
	}
	if k.Kind == kmodel.KindCanary {
		return "canary"
	}
	return "active"
}

func statusStyle(k Key) lipgloss.Style {
	switch statusLabel(k) {
	case "disabled":
		return warnStyle
	case "revoked", "canary":
		return badStyle
	default:
		return okStyle
	}
}

func todayLine(k Key) string {
	s := "$" + money.FormatUSD(k.SpendToday)
	if k.SpendOpen > 0 {
		s += " (+$" + money.FormatUSD(k.SpendOpen) + ")"
	}
	return s
}

func capLine(micro *int64) string {
	if micro == nil {
		return "—"
	}
	return "$" + money.FormatUSD(*micro)
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("01-02 15:04")
}

func fit(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if lipgloss.Width(s) <= n {
		return s + strings.Repeat(" ", n-lipgloss.Width(s))
	}
	r := []rune(s)
	for len(r) > 0 && lipgloss.Width(string(r)) > n {
		r = r[:len(r)-1]
	}
	return string(r)
}

func scrollText(s string, n int) string {
	if n <= 0 {
		return s
	}
	lines := strings.Split(s, "\n")
	if n >= len(lines) {
		n = len(lines) - 1
	}
	if n < 0 {
		return s
	}
	return strings.Join(lines[n:], "\n")
}

func clip(s string, n int) string {
	if n <= 0 {
		return s
	}
	lines := strings.Split(s, "\n")
	if len(lines) <= n {
		return s
	}
	return strings.Join(lines[:n], "\n")
}
