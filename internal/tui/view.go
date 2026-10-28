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
	accent      = lipgloss.AdaptiveColor{Light: "27", Dark: "75"}
	selBg       = lipgloss.AdaptiveColor{Light: "254", Dark: "237"}
	dimStyle    = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "242", Dark: "245"})
	okStyle     = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "28", Dark: "42"})
	warnStyle   = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "172", Dark: "214"})
	badStyle    = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "160", Dark: "203"})
	canaryStyle = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "127", Dark: "177"})
	plainStyle  = lipgloss.NewStyle()
	tabStyle    = lipgloss.NewStyle().Foreground(accent).Bold(true).Underline(true)
	titleStyle  = lipgloss.NewStyle().Bold(true)
	markStyle   = lipgloss.NewStyle().Foreground(accent).Bold(true)
	errStyle    = badStyle
	noteStyle   = okStyle
	// Finding bars use a tinted background, the same idea as a status chip:
	// dark red for high, dark amber for medium, a quiet gray for low.
	highBand = lipgloss.NewStyle().
			Foreground(lipgloss.AdaptiveColor{Light: "160", Dark: "210"}).
			Background(lipgloss.AdaptiveColor{Light: "224", Dark: "52"})
	medBand = lipgloss.NewStyle().
		Foreground(lipgloss.AdaptiveColor{Light: "172", Dark: "221"}).
		Background(lipgloss.AdaptiveColor{Light: "230", Dark: "58"})
	lowBand = lipgloss.NewStyle().
		Foreground(lipgloss.AdaptiveColor{Light: "238", Dark: "252"}).
		Background(lipgloss.AdaptiveColor{Light: "254", Dark: "236"})
)

// timeLayout is the one timestamp format on every screen.
const timeLayout = "2006-01-02 15:04 UTC"

const helpText = `keman

views     1 keys · 2 detections · 3 audit · 4 setup · tab next
lists     j/k or arrows move · enter open · / filter this view
keys      p policy: lock to addresses or countries, expiry, limits
          r rotate (new key, old one stops later or now)
          d disable · e enable · x revoke (type the name)
setup     a add upstream · c add credential · n new virtual key
forms     tab or arrows change field · left/right change a choice
          enter next field, then save · esc cancel
quit      q, except while typing in a field · ctrl+c always

lock      open means a leaked copy works from anywhere. Set addresses in p.
alerts    rules that fired on the key in the last 7 days.
Times are UTC. Money is in dollars and only applies to LLM upstreams.
Type the admin token when asked, unless KEMAN_ADMIN_TOKEN is set.
keman scan, keman exposure, keman canary, credential rotation,
rekey, admin-token rotate, and alerts are on the CLI.
`

func (m model) View() string {
	body := m.renderBody()
	if m.overlay == overlayDetail || (m.overlay == overlayNone && m.screen == screenSetup) {
		body = scrollText(body, m.scroll)
	}
	budget := m.bodyBudget()
	if m.overlay != overlayToken {
		body = cutLines(clip(body, budget), m.totalWidth())
	}
	body = strings.TrimSuffix(body, "\n")
	var b strings.Builder
	b.WriteString(m.header())
	b.WriteString("\n")
	b.WriteString(body)
	b.WriteString("\n")
	if budget > 0 {
		for n := lineCount(body); n < budget; n++ {
			b.WriteString("\n")
		}
	}
	b.WriteString(m.statusLine())
	b.WriteString("\n")
	// No newline after the footer: it would make the frame one line taller
	// than the terminal and scroll the header off the top.
	b.WriteString(m.footer())
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
	case overlayRotate:
		return m.renderRotate()
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
	left := titleStyle.Render("keman") + dimStyle.Render(" · "+host)
	labels := []struct {
		name string
		s    screen
	}{
		{"1 keys", screenKeys},
		{"2 detections", screenDetections},
		{"3 audit", screenAudit},
		{"4 setup", screenSetup},
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
	if m.width == 0 {
		return left + "  " + right
	}
	if gap < 2 {
		// Too narrow for both: keep the tabs, they carry the shortcuts.
		return fit(right, m.width)
	}
	return left + strings.Repeat(" ", gap) + right
}

// statusLine is the one place for loading, error, and success feedback.
// It is always one line, so the footer never moves.
func (m model) statusLine() string {
	w := m.totalWidth()
	switch {
	case m.errMsg != "":
		return errStyle.Render(fit("! "+m.errMsg, w))
	case m.note != "":
		return noteStyle.Render(fit("✓ "+m.note, w))
	case m.loading && !m.hasData():
		return dimStyle.Render("loading…")
	}
	return ""
}

func (m model) footer() string {
	return dimStyle.Render(fit(m.footerText(), m.totalWidth()))
}

func (m model) footerText() string {
	if m.filtering {
		return "type to filter · enter keep · esc clear"
	}
	save := "enter next"
	if m.onLastField() {
		save = "enter save"
	}
	switch m.overlay {
	case overlayToken:
		return "enter clear it from the screen · q quit"
	case overlayRevoke:
		return "enter revoke · esc cancel"
	case overlayRotate:
		return "←/→ grace · enter rotate · esc cancel"
	case overlayConfirm:
		return "enter switch to auto_disable · esc back to the form"
	case overlayPolicy, overlayCreate, overlayUpstream, overlayCredential:
		return "tab/↑↓ field · ←/→ choice · " + save + " · esc cancel"
	case overlayAdmin:
		return "enter continue · esc quit"
	case overlayHelp:
		return "esc back · q quit"
	case overlayDetail:
		return "p policy · r rotate · d disable · e enable · x revoke · j/k scroll · esc back · q quit"
	}
	switch m.screen {
	case screenDetections:
		return "j/k move · enter open key · / filter · 1-4 views · ? help · q quit"
	case screenAudit:
		return "j/k move · enter open key · / filter · 1-4 views · ? help · q quit"
	case screenSetup:
		return "a upstream · c credential · n new key · j/k scroll · 1-4 views · ? help · q quit"
	default:
		return "enter open · n new · p policy · r rotate · d disable · x revoke · / filter · ? help · q quit"
	}
}

// column is one table column. A flex column takes the remaining width.
type column struct {
	title string
	width int
	flex  bool
}

// cell is one table value. A nil style renders plain text.
type cell struct {
	text  string
	style *lipgloss.Style
}

func txt(s string) cell { return cell{text: s} }

func styled(s string, st lipgloss.Style) cell { return cell{text: s, style: &st} }

// table renders the shared list layout: a dim header, padded columns cut
// with an ellipsis, and a full-width selection. Columns that do not fit are
// dropped from the right instead of wrapping. cursor < 0 means no selection.
func (m model) table(cols []column, rows [][]cell, cursor, start, end int) string {
	w := m.totalWidth()
	widths := make([]int, 0, len(cols))
	used := 2
	for i, c := range cols {
		need := c.width
		if i > 0 {
			need += 2
		}
		if i > 0 && used+need > w {
			break
		}
		widths = append(widths, c.width)
		used += need
	}
	if len(widths) == 0 {
		return ""
	}
	last := len(widths) - 1
	if used > w {
		widths[last] -= used - w
		if widths[last] < 1 {
			widths[last] = 1
		}
	} else if cols[last].flex {
		widths[last] += w - used
	}
	var b strings.Builder
	head := make([]string, len(widths))
	for i := range widths {
		head[i] = fit(cols[i].title, widths[i])
	}
	b.WriteString(dimStyle.Render("  " + strings.Join(head, "  ")))
	b.WriteString("\n")
	for r := start; r < end; r++ {
		b.WriteString(m.tableRow(rows[r], widths, r == cursor, w))
		b.WriteString("\n")
	}
	return b.String()
}

func (m model) tableRow(row []cell, widths []int, selected bool, w int) string {
	paint := func(st lipgloss.Style, s string) string {
		if selected {
			st = st.Background(selBg)
		}
		return st.Render(s)
	}
	var b strings.Builder
	if selected {
		b.WriteString(paint(markStyle, "› "))
	} else {
		b.WriteString("  ")
	}
	used := 2
	for i, width := range widths {
		if i > 0 {
			b.WriteString(paint(plainStyle, "  "))
			used += 2
		}
		c := cell{}
		if i < len(row) {
			c = row[i]
		}
		st := plainStyle
		if c.style != nil {
			st = *c.style
		}
		if selected {
			st = st.Bold(true)
		}
		b.WriteString(paint(st, fit(c.text, width)))
		used += width
	}
	if selected && used < w {
		b.WriteString(paint(plainStyle, strings.Repeat(" ", w-used)))
	}
	return b.String()
}

func (m model) renderKeys() string {
	rows := m.visibleKeys()
	var b strings.Builder
	b.WriteString(m.filterBanner())
	if len(rows) == 0 {
		switch {
		case len(m.keys) > 0:
			b.WriteString("No keys match the filter.\n")
		case !m.loaded[screenKeys]:
		case len(m.ups) == 0:
			b.WriteString("No virtual keys yet.\n\n")
			b.WriteString("Press a to add an upstream. The credential and key forms follow.\n")
		case len(m.creds) == 0:
			b.WriteString("No virtual keys yet.\n\n")
			b.WriteString("Press c to add a credential, then n to create a key.\n")
		default:
			b.WriteString("No virtual keys yet.\n\n")
			b.WriteString("Press n to create a key.\n")
		}
		return b.String()
	}
	b.WriteString(m.exposureBanner())
	cols := []column{
		{title: "name", width: 16},
		{title: "status", width: 9},
		{title: "kind", width: 8},
		{title: "lock", width: 10},
		{title: "alerts 7d", width: 9},
		{title: "expires", width: 9},
		{title: "last seen", width: 14, flex: true},
	}
	now := time.Now()
	cells := make([][]cell, len(rows))
	for i, k := range rows {
		lock, lockSt := lockLabel(k)
		alerts := styled("0", dimStyle)
		if k.Detections7d > 0 {
			alerts = styled(strconv.Itoa(k.Detections7d), badStyle)
		}
		exp, expSt := expiresLabel(k, now)
		cells[i] = []cell{
			txt(displayName(k)),
			styled(statusLabel(k), statusStyle(k)),
			styled(kindLabel(k), kindStyle(k)),
			styled(lock, lockSt),
			alerts,
			styled(exp, expSt),
			txt(lastSeenLabel(k, now)),
		}
	}
	start, end := m.span(len(rows))
	b.WriteString(m.table(cols, cells, m.cursor, start, end))
	return b.String()
}

// exposureBanner sums up the keys that would be easy to abuse if leaked.
func (m model) exposureBanner() string {
	open, never, idle := 0, 0, 0
	for _, k := range m.keys {
		for _, x := range k.Exposure {
			switch x.Code {
			case "network_open":
				open++
			case "no_expiry":
				never++
			case "idle":
				idle++
			}
		}
	}
	var parts []string
	if open > 0 {
		parts = append(parts, plural(open, "key works", "keys work")+" from any address")
	}
	if never > 0 {
		parts = append(parts, plural(never, "key never expires", "keys never expire"))
	}
	if idle > 0 {
		parts = append(parts, plural(idle, "key is", "keys are")+" unused for 30+ days")
	}
	if len(parts) == 0 {
		return ""
	}
	return warnStyle.Render(fit("! "+strings.Join(parts, " · ")+" · open one and press p", m.totalWidth())) + "\n"
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

// lockLabel is what limits where the key works. open means anywhere.
func lockLabel(k Key) (string, lipgloss.Style) {
	if k.Kind == kmodel.KindCanary {
		return "decoy", canaryStyle
	}
	var cidr, country bool
	if k.Policy != nil {
		cidr, country = len(k.Policy.CIDRs) > 0, len(k.Policy.Countries) > 0
	}
	switch {
	case cidr && country:
		return "ip+country", okStyle
	case cidr:
		return "ip", okStyle
	case country:
		return "country", okStyle
	}
	if k.Status != kmodel.StatusActive {
		return "open", dimStyle
	}
	return "open", warnStyle
}

func expiresLabel(k Key, now time.Time) (string, lipgloss.Style) {
	if k.ExpiresAt == nil {
		if k.Kind == kmodel.KindCanary || k.Status != kmodel.StatusActive {
			return "never", dimStyle
		}
		return "never", warnStyle
	}
	left := k.ExpiresAt.Sub(now)
	switch {
	case left <= 0:
		return "expired", dimStyle
	case left < 7*24*time.Hour:
		return "in " + ago(left), warnStyle
	default:
		return "in " + ago(left), plainStyle
	}
}

func lastSeenLabel(k Key, now time.Time) string {
	if k.LastSeen.IsZero() {
		return "never"
	}
	s := ago(now.Sub(k.LastSeen)) + " ago"
	if k.LastIP != "" {
		s += " · " + k.LastIP
	}
	if k.LastCountry != "" {
		s += " " + k.LastCountry
	}
	return s
}

// ago is a short span such as 5m, 3h or 12d.
func ago(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "<1m"
	case d < time.Hour:
		return strconv.Itoa(int(d/time.Minute)) + "m"
	case d < 48*time.Hour:
		return strconv.Itoa(int(d/time.Hour)) + "h"
	default:
		return strconv.Itoa(int(d/(24*time.Hour))) + "d"
	}
}

func (m model) renderDetections() string {
	rows := m.visibleDets()
	var b strings.Builder
	b.WriteString(m.filterBanner())
	if len(rows) == 0 {
		switch {
		case len(m.dets) > 0:
			b.WriteString("No detections match the filter.\n")
		case !m.loaded[screenDetections]:
		default:
			b.WriteString("No detections. Rules fire on abuse, not on normal traffic.\n")
		}
		return b.String()
	}
	cols := []column{
		{title: "time", width: len(timeLayout)},
		{title: "severity", width: 8},
		{title: "key", width: 14},
		{title: "rule", width: 10, flex: true},
	}
	cells := make([][]cell, len(rows))
	for i, d := range rows {
		cells[i] = []cell{
			txt(fmtTime(d.Time)),
			styled(d.Severity, severityStyle(d.Severity)),
			txt(m.keyLabel(d.KeyID)),
			txt(d.Rule),
		}
	}
	start, end := m.span(len(rows))
	b.WriteString(m.table(cols, cells, m.cursor, start, end))
	return b.String()
}

func (m model) renderAudit() string {
	rows := m.visibleAudits()
	var b strings.Builder
	b.WriteString(m.filterBanner())
	if len(rows) == 0 {
		switch {
		case len(m.audits) > 0:
			b.WriteString("No audit entries match the filter.\n")
		case !m.loaded[screenAudit]:
		default:
			b.WriteString("No audit entries yet.\n")
		}
		return b.String()
	}
	cols := []column{
		{title: "time", width: len(timeLayout)},
		{title: "action", width: 18},
		{title: "target", width: 16},
		{title: "actor", width: 10, flex: true},
	}
	cells := make([][]cell, len(rows))
	for i, a := range rows {
		cells[i] = []cell{
			txt(fmtTime(a.Time)),
			txt(a.Action),
			txt(m.keyLabel(a.Target)),
			txt(a.Actor),
		}
	}
	start, end := m.span(len(rows))
	b.WriteString(m.table(cols, cells, m.cursor, start, end))
	return b.String()
}

func (m model) renderSetup() string {
	if !m.loaded[screenSetup] {
		return ""
	}
	var b strings.Builder
	b.WriteString(titleStyle.Render("upstreams"))
	b.WriteString("\n")
	if len(m.ups) == 0 {
		b.WriteString("  none · press a to add one\n")
	} else {
		cells := make([][]cell, len(m.ups))
		for i, u := range m.ups {
			tls := "off"
			if u.TLS {
				tls = "on"
			}
			cells[i] = []cell{txt(u.Name), txt(u.Profile), txt(u.Host + ":" + strconv.Itoa(u.Port)), txt(tls)}
		}
		b.WriteString(m.table([]column{
			{title: "name", width: 16}, {title: "profile", width: 9}, {title: "address", width: 28, flex: true}, {title: "tls", width: 3},
		}, cells, -1, 0, len(cells)))
	}
	b.WriteString("\n")
	b.WriteString(titleStyle.Render("credentials"))
	b.WriteString("\n")
	if len(m.creds) == 0 {
		b.WriteString("  none · press c to add one\n")
	} else {
		cells := make([][]cell, len(m.creds))
		for i, c := range m.creds {
			last := c.Last4
			if last == "" {
				last = "—"
			}
			cells[i] = []cell{txt(c.Name), txt(m.upstreamName(c.UpstreamID)), txt(c.AuthStyle), txt("…" + last)}
		}
		b.WriteString(m.table([]column{
			{title: "name", width: 16}, {title: "upstream", width: 16}, {title: "auth", width: 8}, {title: "key", width: 8, flex: true},
		}, cells, -1, 0, len(cells)))
	}
	b.WriteString("\n")
	b.WriteString(titleStyle.Render("alert destinations"))
	b.WriteString(dimStyle.Render("  (managed with keman alert)"))
	b.WriteString("\n")
	if len(m.alerts) == 0 {
		b.WriteString("  none\n")
	} else {
		cells := make([][]cell, len(m.alerts))
		for i, a := range m.alerts {
			cells[i] = []cell{txt(a.Kind), txt(a.ID), txt(a.URL)}
		}
		b.WriteString(m.table([]column{
			{title: "kind", width: 8}, {title: "id", width: 10}, {title: "url", width: 20, flex: true},
		}, cells, -1, 0, len(cells)))
	}
	b.WriteString("\n")
	b.WriteString(dimStyle.Render(fit("Rotate, rekey, admin-token rotate, and alerts stay on the CLI.", m.totalWidth())))
	b.WriteString("\n")
	return b.String()
}

func (m model) renderDetail() string {
	k, ok := m.keyByID(m.detailID)
	if !ok {
		return "That key is no longer listed.\n"
	}
	w := m.totalWidth()
	now := time.Now()
	leftW, rightW, split := detailColumns(w)
	left := m.detailRail(k, innerWidth(leftW), now)
	title, calls := m.detailCalls(k, innerWidth(rightW), now)
	if !split {
		return panel(displayName(k), left, w) + "\n" + panel(title, calls, w) + "\n"
	}
	return beside(displayName(k), left, leftW, title, calls, rightW) + "\n"
}

// detailColumns is the wide layout: a rail for the key, the rest for calls.
// Below 100 columns the two panels stack.
func detailColumns(w int) (left, right int, split bool) {
	if w < 100 {
		return w, w, false
	}
	left = 40
	if w >= 120 {
		left = 52
	}
	if left > w-48 {
		left = w - 48
	}
	if left < 32 {
		return w, w, false
	}
	return left, w - left, true
}

func innerWidth(panelWidth int) int {
	if panelWidth < 8 {
		return panelWidth
	}
	return panelWidth - 4
}

func (m model) detailRail(k Key, inner int, now time.Time) string {
	lines := []string{idStatusLine(k, inner)}
	lines = append(lines, detailNoteLines(k, inner)...)
	if len(k.Exposure) > 0 {
		lines = append(lines, "")
		for i, x := range k.Exposure {
			if i > 0 {
				lines = append(lines, "")
			}
			label, phrase := exposureBandText(x)
			lines = append(lines, fillBand(exposureBandStyle(x.Severity), label, phrase, inner))
			if cmd := exposureCommand(x); cmd != "" {
				lines = append(lines, dimStyle.Render("  "+cmd))
			}
		}
	}
	if stats := m.detailStatLines(k, now); len(stats) > 0 {
		lines = append(lines, "")
		lines = append(lines, stats...)
	}
	return strings.Join(lines, "\n")
}

func idStatusLine(k Key, inner int) string {
	status := statusStyle(k).Render(statusLabel(k))
	if k.Name == "" {
		pad := inner - lipgloss.Width(status)
		if pad < 0 {
			pad = 0
		}
		return strings.Repeat(" ", pad) + status
	}
	left := dimStyle.Render(k.ID)
	gap := inner - lipgloss.Width(left) - lipgloss.Width(status)
	if gap < 1 {
		return left + " " + status
	}
	return left + strings.Repeat(" ", gap) + status
}

func detailNoteLines(k Key, width int) []string {
	var head string
	var hs lipgloss.Style
	var rest string
	switch {
	case k.Kind == kmodel.KindCanary:
		head, hs = "decoy", canaryStyle
		rest = "any use raises a critical alert and never reaches the upstream"
	case len(k.Exposure) == 0 && k.Status == kmodel.StatusActive:
		head, hs = "✓ locked down", okStyle
		rest = "limited to known networks, expires, in use"
	default:
		return nil
	}
	return wrapLead(head, hs, rest, width)
}

func wrapLead(head string, hs lipgloss.Style, rest string, width int) []string {
	wrapped := wrapPlain(head+" · "+rest, width)
	var out []string
	for i, line := range wrapped {
		if i == 0 && strings.HasPrefix(line, head) {
			out = append(out, hs.Render(head)+dimStyle.Render(strings.TrimPrefix(line, head)))
			continue
		}
		out = append(out, dimStyle.Render(line))
	}
	return out
}

func wrapPlain(s string, width int) []string {
	if width <= 0 || lipgloss.Width(s) <= width {
		if s == "" {
			return nil
		}
		return []string{s}
	}
	var lines []string
	var cur string
	for _, word := range strings.Fields(s) {
		if cur == "" {
			cur = word
			continue
		}
		if lipgloss.Width(cur)+1+lipgloss.Width(word) <= width {
			cur += " " + word
			continue
		}
		lines = append(lines, cur)
		cur = word
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

func exposureBandText(x Exposure) (label, phrase string) {
	switch x.Code {
	case "network_open":
		return "open network", "anyone who has it can call it"
	case "no_expiry":
		return "no expiry", "a leaked copy keeps working"
	case "idle":
		return "unused", ""
	case "expires_soon":
		return "expires soon", ""
	default:
		if x.Message != "" {
			return x.Message, ""
		}
		return x.Code, ""
	}
}

func exposureCommand(x Exposure) string {
	switch x.Code {
	case "network_open":
		return "set --cidr <egress>/32"
	case "no_expiry":
		return "key expiry 90d"
	case "idle":
		return "key revoke"
	case "expires_soon":
		return "key rotate"
	default:
		return strings.TrimPrefix(x.Fix, "keman ")
	}
}

func exposureBandStyle(severity string) lipgloss.Style {
	switch severity {
	case "critical", "high":
		return highBand
	case "medium":
		return medBand
	default:
		return lowBand
	}
}

// fillBand paints a full-width finding bar. The label is bold; the phrase
// sits on the same bar when it fits.
func fillBand(base lipgloss.Style, label, phrase string, width int) string {
	if width <= 0 {
		return ""
	}
	textW := width
	inset := ""
	if width >= 4 {
		textW = width - 2
		inset = " "
	}
	if lipgloss.Width(label) > textW {
		label = strings.TrimRight(fit(label, textW), " ")
	}
	rest := ""
	if phrase != "" && lipgloss.Width(label)+2+lipgloss.Width(phrase) <= textW {
		rest = "  " + phrase
	}
	pad := textW - lipgloss.Width(label) - lipgloss.Width(rest)
	if pad < 0 {
		pad = 0
	}
	mid := base.Bold(true).Render(label) + base.Render(rest+strings.Repeat(" ", pad))
	if inset == "" {
		return mid
	}
	return base.Render(inset) + mid + base.Render(inset)
}

func (m model) detailStatLines(k Key, now time.Time) []string {
	if !m.detailLoaded {
		return []string{"loading…"}
	}
	u := m.detailUsage
	var lines []string
	if u.Requests == 0 {
		lines = append(lines, dimStyle.Render("no requests yet"))
	} else {
		line := fmt.Sprintf("%d requests", u.Requests)
		if !u.LastSeen.IsZero() {
			line += " · last " + shortTime(u.LastSeen, now)
		}
		lines = append(lines, line)
		switch len(u.Clients) {
		case 0:
		case 1:
			lines = append(lines, clientWhere(u.Clients[0]))
		default:
			for _, c := range u.Clients {
				lines = append(lines, fmt.Sprintf("%s  %d", clientWhere(c), c.Requests))
			}
		}
	}
	if m.isLLM(k) {
		lines = append(lines, spendLines(k, u)...)
		if u.TokensIn > 0 || u.TokensOut > 0 || u.Cached > 0 || u.CacheWrite > 0 {
			lines = append(lines, tokenLine(u))
		}
	}
	lines = append(lines, policyLines(k, now)...)
	blocked := 0
	for _, r := range u.Recent {
		if r.BlockedCode != "" {
			blocked++
		}
	}
	if blocked > 0 {
		lines = append(lines, kvLine("blocked", badStyle.Render(strconv.Itoa(blocked))))
	}
	if len(m.detailDets) > 0 {
		lines = append(lines, "", dimStyle.Render("detections"))
		for i := len(m.detailDets) - 1; i >= 0; i-- {
			d := m.detailDets[i]
			lines = append(lines, fmtTime(d.Time)+"  "+severityStyle(d.Severity).Render(d.Severity)+"  "+d.Rule)
		}
	}
	return lines
}

func spendLines(k Key, u KeyUsage) []string {
	var lines []string
	if k.SpendToday > 0 || k.SpendOpen > 0 {
		s := "today " + usdBrief(k.SpendToday)
		if k.SpendOpen > 0 {
			s += " (+" + usd(k.SpendOpen) + ")"
		}
		lines = append(lines, s)
	}
	if k.SpendMonth > 0 {
		lines = append(lines, "month "+usdBrief(k.SpendMonth))
	}
	if k.SpendToday == 0 && k.SpendMonth == 0 && k.SpendOpen == 0 && u.CostMicro > 0 {
		lines = append(lines, "spend "+usdBrief(u.CostMicro))
	}
	return lines
}

func tokenLine(u KeyUsage) string {
	s := fmt.Sprintf("in %d · out %d", u.TokensIn, u.TokensOut)
	if u.Cached > 0 {
		s += fmt.Sprintf(" · cached %d", u.Cached)
	}
	if u.CacheWrite > 0 {
		s += fmt.Sprintf(" · cache write %d", u.CacheWrite)
	}
	return s
}

func policyLines(k Key, now time.Time) []string {
	p := k.Policy
	if p == nil {
		return nil
	}
	var lines []string
	if len(p.CIDRs) > 0 {
		lines = append(lines, kvLine("addresses", strings.Join(p.CIDRs, ", ")))
	}
	if len(p.Countries) > 0 {
		lines = append(lines, kvLine("countries", strings.Join(p.Countries, ", ")))
	}
	if k.ExpiresAt != nil {
		exp, st := expiresLabel(k, now)
		lines = append(lines, kvLine("expires", st.Render(exp+" · "+fmtTime(*k.ExpiresAt))))
	}
	if p.Mode != "" && p.Mode != kmodel.ModeAlertOnly {
		lines = append(lines, kvLine("on abuse", p.Mode))
	}
	if p.RPM != nil {
		lines = append(lines, kvLine("rate limit", strconv.Itoa(*p.RPM)+" per minute"))
	}
	if p.DailyCapMicro != nil {
		lines = append(lines, kvLine("daily cap", capLine(p.DailyCapMicro)))
	}
	if p.MonthlyCapMicro != nil {
		lines = append(lines, kvLine("monthly cap", capLine(p.MonthlyCapMicro)))
	}
	if len(p.Paths) > 0 {
		lines = append(lines, kvLine("paths", strings.Join(p.Paths, ", ")))
	}
	if len(p.Models) > 0 {
		lines = append(lines, kvLine("models", strings.Join(p.Models, ", ")))
	}
	return lines
}

func (m model) detailCalls(k Key, inner int, now time.Time) (string, string) {
	u := m.detailUsage
	if !m.detailLoaded {
		return "requests", "loading…"
	}
	if len(u.Recent) == 0 {
		return "requests", dimStyle.Render("none")
	}
	llm := k.Kind != kmodel.KindCanary && m.isLLM(k)
	shared := sharedOperation(u.Recent)
	title := "requests"
	if shared != "" {
		title += " · " + shared
	}
	showIP := distinctIPs(u.Recent) > 1
	var plain []string
	showStatus := false
	for _, r := range u.Recent {
		if r.Status >= 400 || r.BlockedCode != "" {
			showStatus = true
		}
		plain = append(plain, requestStatus(r))
	}
	timeW, statusW, tokW, costW := 5, 0, 0, 0
	type built struct {
		when, status, name, tokens, cost string
	}
	rows := make([]built, len(u.Recent))
	for i, r := range u.Recent {
		row := built{when: shortTime(r.Time, now), name: requestName(r, llm, shared, showIP)}
		if showStatus {
			row.status = plain[i]
			if n := lipgloss.Width(row.status); n > statusW {
				statusW = n
			}
		}
		if n := lipgloss.Width(row.when); n > timeW {
			timeW = n
		}
		if llm {
			row.tokens = fmt.Sprintf("%d → %d", r.TokensIn, r.TokensOut)
			if n := lipgloss.Width(row.tokens); n > tokW {
				tokW = n
			}
			if r.CostMicro != nil {
				row.cost = usd(*r.CostMicro)
				if r.CostEstimated {
					row.cost += " estimated"
				}
				if n := lipgloss.Width(row.cost); n > costW {
					costW = n
				}
			}
		}
		rows[i] = row
	}
	fixed := timeW
	if statusW > 0 {
		fixed += 2 + statusW
	}
	fixed += 2
	if tokW > 0 {
		fixed += 2 + tokW
	}
	if costW > 0 {
		fixed += 2 + costW
	}
	modelW := inner - fixed
	if modelW < 1 {
		modelW = 1
	}
	var lines []string
	for _, row := range rows {
		var b strings.Builder
		b.WriteString(dimStyle.Render(align(row.when, timeW, false)))
		if statusW > 0 {
			b.WriteString("  ")
			cell := align(row.status, statusW, false)
			if row.status != "" {
				cell = badStyle.Render(cell)
			}
			b.WriteString(cell)
		}
		b.WriteString("  ")
		b.WriteString(align(row.name, modelW, false))
		if tokW > 0 {
			b.WriteString("  ")
			b.WriteString(dimStyle.Render(align(row.tokens, tokW, true)))
		}
		if costW > 0 {
			b.WriteString("  ")
			b.WriteString(align(row.cost, costW, true))
		}
		lines = append(lines, b.String())
	}
	return title, strings.Join(lines, "\n")
}

func requestName(r UsageRequest, llm bool, shared string, showIP bool) string {
	name := r.Model
	if !llm || name == "" {
		if shared == "" && r.Operation != "" {
			name = r.Operation
		} else if name == "" {
			name = "—"
		}
	}
	if showIP && r.IP != "" {
		if name == "—" {
			name = r.IP
		} else {
			name += "  " + r.IP
		}
	}
	return name
}

func requestStatus(r UsageRequest) string {
	s := ""
	if r.Status >= 400 {
		s = strconv.Itoa(r.Status)
	}
	if r.BlockedCode != "" {
		if s != "" {
			s += " "
		}
		s += r.BlockedCode
	}
	return s
}

func distinctIPs(rs []UsageRequest) int {
	seen := map[string]struct{}{}
	for _, r := range rs {
		if r.IP != "" {
			seen[r.IP] = struct{}{}
		}
	}
	return len(seen)
}

func sharedOperation(rs []UsageRequest) string {
	if len(rs) == 0 || rs[0].Operation == "" {
		return ""
	}
	op := rs[0].Operation
	for _, r := range rs[1:] {
		if r.Operation != op {
			return ""
		}
	}
	return op
}

func align(s string, w int, right bool) string {
	if w <= 0 {
		return ""
	}
	if lipgloss.Width(s) > w {
		return fit(s, w)
	}
	pad := strings.Repeat(" ", w-lipgloss.Width(s))
	if right {
		return pad + s
	}
	return s + pad
}

func kvLine(label, value string) string {
	return strings.TrimSuffix(kv(label, value), "\n")
}

func usdBrief(micro int64) string {
	if micro > 0 && micro < 10_000 {
		return "< $0.01"
	}
	return usd(micro)
}

func shortTime(t, now time.Time) string {
	if t.IsZero() {
		return "—"
	}
	t, now = t.UTC(), now.UTC()
	switch {
	case t.Year() == now.Year() && t.YearDay() == now.YearDay():
		return t.Format("15:04")
	case t.Year() == now.Year():
		return t.Format("01-02 15:04")
	default:
		return t.Format("2006-01-02 15:04")
	}
}

// beside draws two bordered panels on one row, stretched to the same height.
func beside(lt, lc string, lw int, rt, rc string, rw int) string {
	lc, ln := panelBody(lc)
	rc, rn := panelBody(rc)
	n := ln
	if rn > n {
		n = rn
	}
	return lipgloss.JoinHorizontal(lipgloss.Top,
		panel(lt, padBody(lc, ln, n), lw),
		panel(rt, padBody(rc, rn, n), rw),
	)
}

func panelBody(c string) (string, int) {
	c = strings.TrimSuffix(c, "\n")
	if c == "" {
		return "", 1
	}
	return c, lineCount(c)
}

func padBody(c string, lines, n int) string {
	if n < lines {
		n = lines
	}
	// panel trims one trailing newline before splitting, so the extra
	// newline is what keeps the last blank row.
	return c + strings.Repeat("\n", n-lines+1)
}

// isLLM reports whether the key's upstream tracks tokens and spend. When the
// setup lists have not loaded, it says yes so nothing is hidden.
func (m model) isLLM(k Key) bool {
	for _, c := range m.creds {
		if c.ID != k.CredentialID {
			continue
		}
		for _, u := range m.ups {
			if u.ID == c.UpstreamID {
				return u.Profile != "generic"
			}
		}
	}
	return true
}

// panel draws a rounded box with its title in the top border. Lines wider
// than the box are cut; the result is exactly width cells wide.
func panel(title, content string, width int) string {
	if width < 8 {
		return content
	}
	inner := width - 4
	cut := lipgloss.NewStyle().MaxWidth(inner)
	bd := dimStyle
	label := " " + title + " "
	if lipgloss.Width(label) > width-5 {
		label = fit(label, width-5)
	}
	var b strings.Builder
	b.WriteString(bd.Render("╭─") + markStyle.Render(label) + bd.Render(strings.Repeat("─", width-3-lipgloss.Width(label))+"╮"))
	for _, l := range strings.Split(strings.TrimSuffix(content, "\n"), "\n") {
		if lipgloss.Width(l) > inner {
			l = cut.Render(l)
		}
		b.WriteString("\n" + bd.Render("│") + " " + l + strings.Repeat(" ", inner-lipgloss.Width(l)) + " " + bd.Render("│"))
	}
	b.WriteString("\n" + bd.Render("╰"+strings.Repeat("─", width-2)+"╯"))
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

// form renders the shared form layout: a title, one row per field, and a
// hint for the focused field.
func (m model) form(title string, rows []string, hint string) string {
	var b strings.Builder
	b.WriteString(titleStyle.Render(title))
	b.WriteString("\n\n")
	for _, r := range rows {
		b.WriteString(r)
	}
	if hint != "" {
		b.WriteString("\n")
		b.WriteString(dimStyle.Render(hint))
		b.WriteString("\n")
	}
	return b.String()
}

// fieldLine is one form row. A focused choice shows its arrows.
func fieldLine(on bool, label, value string, choice bool) string {
	mark := "  "
	l := fit(label, 12)
	if on {
		mark = markStyle.Render("› ")
		l = titleStyle.Render(l)
		if choice {
			value = "‹ " + value + " ›"
		}
	}
	return mark + l + value + "\n"
}

var policyHints = []string{
	"alert_only alerts · dry_run records what auto_disable would do · auto_disable turns the key off",
	"Allowed client addresses, comma separated, such as 203.0.113.7/32. Empty allows any.",
	"Two-letter country codes, such as US, DE. Needs a GeoIP database. Empty allows any.",
	"When the key stops working: 30d, 2026-12-31, an RFC3339 time, or empty for never.",
	"Requests per minute. Leave empty for no limit.",
	"Dollars per UTC day, such as 1.50. LLM upstreams only. Leave empty for no cap.",
	"Dollars per UTC month, such as 20. LLM upstreams only. Leave empty for no cap.",
}

func (m model) renderPolicy() string {
	rows := []string{
		fieldLine(m.polField == 0, "on abuse", policyModes[m.polMode], true),
		fieldLine(m.polField == 1, "addresses", m.cidrInput.View(), false),
		fieldLine(m.polField == 2, "countries", m.countryInput.View(), false),
		fieldLine(m.polField == 3, "expires", m.expiresInput.View(), false),
		fieldLine(m.polField == 4, "rpm", m.rpmInput.View(), false),
		fieldLine(m.polField == 5, "daily $", m.dailyInput.View(), false),
		fieldLine(m.polField == 6, "monthly $", m.monthlyInput.View(), false),
	}
	return m.form("policy · "+m.policyName, rows, policyHints[m.polField]+"\nPath and model allowlists on this key are kept.")
}

var upstreamHints = []string{
	"A label for this upstream.",
	"openai and anthropic track tokens and spend. generic needs a path list.",
	"Host name only, without https://.",
	"Usually 443.",
	"TLS to the upstream. Leave on for public APIs.",
	"Comma separated, such as POST /v1/chat/completions. * is one segment, ** the rest. Empty uses the profile's built-in list.",
}

func (m model) renderUpstream() string {
	profile := upstreamProfiles[0]
	if m.upProfile >= 0 && m.upProfile < len(upstreamProfiles) {
		profile = upstreamProfiles[m.upProfile]
	}
	tls := "off"
	if m.upTLS {
		tls = "on"
	}
	hint := upstreamHints[m.upField]
	if m.upField == 0 || m.upField == 2 {
		hint += " OpenRouter is only a suggestion; every field is editable."
	}
	return m.form("add upstream", []string{
		fieldLine(m.upField == 0, "name", m.upName.View(), false),
		fieldLine(m.upField == 1, "profile", profile, true),
		fieldLine(m.upField == 2, "host", m.upHost.View(), false),
		fieldLine(m.upField == 3, "port", m.upPort.View(), false),
		fieldLine(m.upField == 4, "tls", tls, true),
		fieldLine(m.upField == 5, "paths", m.upPaths.View(), false),
	}, hint)
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
	var hint string
	switch m.credField {
	case 0:
		hint = "A label for this real key, such as primary."
	case 1:
		hint = "The upstream this key belongs to."
	case 2:
		hint = "environment reads a variable from this shell. type it takes the key in a masked field."
	default:
		if m.credMode == 0 {
			hint = "The name of an environment variable set in the shell that started keman."
		} else {
			hint = "The provider API key. It is masked, stored encrypted, and not shown again."
		}
	}
	return m.form("add credential", []string{
		fieldLine(m.credField == 0, "name", m.credName.View(), false),
		fieldLine(m.credField == 1, "upstream", upName, true),
		fieldLine(m.credField == 2, "from", from, true),
		fieldLine(m.credField == 3, valueLabel, value, false),
	}, hint)
}

func (m model) renderAdmin() string {
	return m.form("admin token", []string{
		fieldLine(true, "token", m.adminInput.View(), false),
	}, "Printed once by keman init. It is masked and kept only in this process.")
}

func (m model) renderCreate() string {
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
	kind := kmodel.KindStandard
	if m.createKind == 1 {
		kind = kmodel.KindCanary
	}
	hints := []string{
		"A label for whoever uses the key, such as laptop or ci.",
		"The real key that requests are forwarded with.",
		"standard works normally. canary is a decoy that alerts on any use.",
	}
	return m.form("new virtual key", []string{
		fieldLine(m.createField == 0, "name", m.nameInput.View(), false),
		fieldLine(m.createField == 1, "credential", cred, true),
		fieldLine(m.createField == 2, "kind", kind, true),
	}, hints[m.createField])
}

func (m model) renderRevoke() string {
	return m.form("revoke · "+m.revokeExpect, []string{
		fieldLine(true, "confirm", m.revokeInput.View(), false),
	}, "Revoke is permanent. Type "+m.revokeExpect+" to confirm. Disable (d) is reversible.")
}

func (m model) renderRotate() string {
	return m.form("rotate · "+m.rotateName, []string{
		fieldLine(true, "old key", rotateGraces[m.rotateGrace].label, true),
	}, "A new key is issued with the same credential and policy, and shown once.\n"+
		"The old key keeps working for the grace period, then expires. Choose none if it leaked.")
}

func (m model) renderConfirm() string {
	name := m.policyName
	if name == "" {
		name = m.policyID
	}
	var b strings.Builder
	b.WriteString(titleStyle.Render("switch " + name + " to auto_disable"))
	b.WriteString("\n\n")
	b.WriteString(dimStyle.Render("dry run, last 7 days"))
	b.WriteString("\n")
	when := "no"
	if m.confirmReport.WouldDisable {
		when = "yes"
		if m.confirmReport.WouldDisableAt != nil {
			when = "yes, at " + fmtTime(*m.confirmReport.WouldDisableAt)
		}
	}
	b.WriteString(kv("would disable", when))
	b.WriteString(kv("would block", strconv.Itoa(m.confirmReport.RequestsWouldBlock)+" requests"))
	b.WriteString(kv("detections", strconv.Itoa(m.confirmReport.Detections)))
	return b.String()
}

func (m model) renderToken() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("new virtual key"))
	if m.tokenName != "" {
		b.WriteString(dimStyle.Render(" · " + m.tokenName))
	}
	b.WriteString("\n\n")
	// Never cut: the secret must be copyable in full.
	b.WriteString(m.token)
	b.WriteString("\n\n")
	b.WriteString(warnStyle.Render("Copy it now. It is shown once."))
	b.WriteString("\n")
	if m.tokenNote != "" {
		b.WriteString("\n" + m.tokenNote + "\n")
	}
	if m.tokenKind == kmodel.KindCanary {
		b.WriteString("\nThis is a decoy. Plant it where a thief would look: a .env in a repo, CI variables,\n")
		b.WriteString("an old config. Any use raises a critical alert. keman canary create prints it as\n")
		b.WriteString("ready-made .env lines with the proxy URL.\n")
	}
	return b.String()
}

func (m model) filterBanner() string {
	f := m.filter()
	if f == "" {
		return ""
	}
	return dimStyle.Render("filter: "+f+"  (esc in / clears)") + "\n"
}

func (m model) totalWidth() int {
	if m.width > 0 {
		return m.width
	}
	return 100
}

func (m model) lineWidth() int {
	return m.totalWidth()
}

// bodyBudget is the number of lines between the header and the status line.
func (m model) bodyBudget() int {
	if m.height <= 0 {
		return 0
	}
	n := m.height - 3
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

// rowBudget is the number of table rows that fit under the table header
// and an optional filter line.
func (m model) rowBudget() int {
	if m.height <= 0 {
		return 20
	}
	n := m.bodyBudget() - 2
	if m.screen == screenKeys && m.overlay == overlayNone && m.exposureBanner() != "" {
		n--
	}
	if n < 1 {
		n = 1
	}
	return n
}

func kv(label, value string) string {
	return dimStyle.Render(fit(label, 14)) + value + "\n"
}

func statusLabel(k Key) string {
	switch k.Status {
	case kmodel.StatusRevoked:
		return "revoked"
	case kmodel.StatusDisabled:
		return "disabled"
	}
	if k.ExpiresAt != nil && !k.ExpiresAt.After(time.Now()) {
		return "expired"
	}
	return "active"
}

func statusStyle(k Key) lipgloss.Style {
	switch statusLabel(k) {
	case "disabled", "expired":
		return warnStyle
	case "revoked":
		return badStyle
	default:
		return okStyle
	}
}

func kindLabel(k Key) string {
	if k.Kind == kmodel.KindCanary {
		return kmodel.KindCanary
	}
	return kmodel.KindStandard
}

func kindStyle(k Key) lipgloss.Style {
	if k.Kind == kmodel.KindCanary {
		return canaryStyle
	}
	return dimStyle
}

func severityStyle(s string) lipgloss.Style {
	switch s {
	case "critical", "high":
		return badStyle
	case "medium":
		return warnStyle
	default:
		return dimStyle
	}
}

// usd is the one dollar format: at least cents, more digits only when a
// sub-cent amount needs them.
func usd(micro int64) string {
	s := money.FormatUSD(micro)
	dot := strings.IndexByte(s, '.')
	switch {
	case dot < 0:
		s += ".00"
	case len(s)-dot == 2:
		s += "0"
	}
	return "$" + s
}

func capLine(micro *int64) string {
	if micro == nil {
		return "—"
	}
	return usd(*micro)
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.UTC().Format(timeLayout)
}

// fit pads s to n cells, or cuts it with an ellipsis.
func fit(s string, n int) string {
	if n <= 0 {
		return ""
	}
	w := lipgloss.Width(s)
	if w <= n {
		return s + strings.Repeat(" ", n-w)
	}
	r := []rune(s)
	for len(r) > 0 && lipgloss.Width(string(r))+1 > n {
		r = r[:len(r)-1]
	}
	return string(r) + "…"
}

// cutLines keeps every line within w cells, so long values never wrap and
// push the footer off the screen.
func cutLines(s string, w int) string {
	lines := strings.Split(s, "\n")
	cut := lipgloss.NewStyle().MaxWidth(w)
	for i, l := range lines {
		if lipgloss.Width(l) > w {
			lines[i] = cut.Render(l)
		}
	}
	return strings.Join(lines, "\n")
}

func lineCount(s string) int {
	if s == "" {
		return 0
	}
	return strings.Count(s, "\n") + 1
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
