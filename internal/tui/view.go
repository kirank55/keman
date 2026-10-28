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
)

// timeLayout is the one timestamp format on every screen.
const timeLayout = "2006-01-02 15:04 UTC"

const helpText = `keman

views     1 keys · 2 detections · 3 audit · 4 setup · tab next
lists     j/k or arrows move · enter open · / filter this view
keys      d disable · e enable · x revoke (type the name) · p policy
setup     a add upstream · c add credential · n new virtual key
forms     tab or arrows change field · left/right change a choice
          enter next field, then save · esc cancel
quit      q, except while typing in a field · ctrl+c always

Money is in dollars. Times are UTC.
Type the admin token when asked, unless KEMAN_ADMIN_TOKEN is set.
Rotate, rekey, admin-token rotate, and alerts stay on the CLI.
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
	case overlayConfirm:
		return "enter switch to auto_disable · esc back to the form"
	case overlayPolicy, overlayCreate, overlayUpstream, overlayCredential:
		return "tab/↑↓ field · ←/→ choice · " + save + " · esc cancel"
	case overlayAdmin:
		return "enter continue · esc quit"
	case overlayHelp:
		return "esc back · q quit"
	case overlayDetail:
		return "d disable · e enable · x revoke · p policy · j/k scroll · esc back · q quit"
	}
	switch m.screen {
	case screenDetections:
		return "j/k move · enter open key · / filter · 1-4 views · ? help · q quit"
	case screenAudit:
		return "j/k move · enter open key · / filter · 1-4 views · ? help · q quit"
	case screenSetup:
		return "a upstream · c credential · n new key · j/k scroll · 1-4 views · ? help · q quit"
	default:
		return "enter open · n new · d disable · e enable · x revoke · p policy · / filter · ? help · q quit"
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
	cols := []column{
		{title: "name", width: 16},
		{title: "status", width: 9},
		{title: "today", width: 18},
		{title: "kind", width: 8},
		{title: "daily cap", width: 10},
		{title: "mode", width: 12, flex: true},
	}
	cells := make([][]cell, len(rows))
	for i, k := range rows {
		cap, mode := "—", "—"
		if k.Kind != kmodel.KindCanary && k.Policy != nil {
			mode = k.Policy.Mode
			if mode == "" {
				mode = kmodel.ModeAlertOnly
			}
			cap = capLine(k.Policy.DailyCapMicro)
		}
		cells[i] = []cell{
			txt(displayName(k)),
			styled(statusLabel(k), statusStyle(k)),
			txt(todayLine(k)),
			styled(kindLabel(k), kindStyle(k)),
			txt(cap),
			txt(mode),
		}
	}
	start, end := m.span(len(rows))
	b.WriteString(m.table(cols, cells, m.cursor, start, end))
	return b.String()
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
	wide := w >= 100
	u := m.detailUsage

	head := titleStyle.Render(displayName(k)) + "  " + dimStyle.Render(k.ID) + "  " +
		statusStyle(k).Render(statusLabel(k)) + "  " + kindStyle(k).Render(kindLabel(k))
	panels := []string{panel("virtual key", head+"\n", w)}

	var spend strings.Builder
	spend.WriteString(kv("today", todayLine(k)))
	spend.WriteString(kv("this month", usd(k.SpendMonth)))
	if k.ExpiresAt != nil {
		spend.WriteString(kv("expires", fmtTime(*k.ExpiresAt)))
	}
	if k.Policy != nil {
		mode := k.Policy.Mode
		if mode == "" {
			mode = kmodel.ModeAlertOnly
		}
		rpm := "unlimited"
		if k.Policy.RPM != nil {
			rpm = strconv.Itoa(*k.Policy.RPM) + " per minute"
		}
		spend.WriteString(kv("mode", mode))
		spend.WriteString(kv("rate limit", rpm))
		spend.WriteString(kv("daily cap", capLine(k.Policy.DailyCapMicro)))
		spend.WriteString(kv("monthly cap", capLine(k.Policy.MonthlyCapMicro)))
		if len(k.Policy.Models) > 0 {
			spend.WriteString(kv("models", strings.Join(k.Policy.Models, ", ")))
		}
		if len(k.Policy.Paths) > 0 {
			spend.WriteString(kv("paths", strings.Join(k.Policy.Paths, ", ")))
		}
	}

	var usage string
	switch {
	case !m.detailLoaded:
		usage = "loading…\n"
	case u.Requests == 0:
		usage = dimStyle.Render("no requests yet") + "\n"
	default:
		usage = usageSummary(u)
	}

	var clients, models strings.Builder
	switch {
	case !m.detailLoaded || u.Requests == 0:
		clients.WriteString(dimStyle.Render("none") + "\n")
		models.WriteString(dimStyle.Render("none") + "\n")
	default:
		if len(u.Clients) == 0 {
			clients.WriteString(dimStyle.Render("none") + "\n")
		}
		for _, c := range u.Clients {
			fmt.Fprintf(&clients, "%s  %d requests  last %s\n", clientWhere(c), c.Requests, fmtTime(c.LastSeen))
		}
		if len(u.Models) == 0 {
			models.WriteString(dimStyle.Render("none") + "\n")
		}
		for _, item := range u.Models {
			name := item.Model
			if name == "" {
				name = "—"
			}
			cost := "—"
			if item.Priced > 0 {
				cost = usd(item.CostMicro)
			}
			fmt.Fprintf(&models, "%s  %d requests  in %d · out %d  %s\n", name, item.Requests, item.TokensIn, item.TokensOut, cost)
		}
	}

	if wide {
		panels = append(panels,
			pair("spend and limits", spend.String(), "usage", usage, w),
			pair("clients · who called", clients.String(), "models · what was called", models.String(), w))
	} else {
		panels = append(panels,
			panel("spend and limits", spend.String(), w),
			panel("usage", usage, w),
			panel("clients · who called", clients.String(), w),
			panel("models · what was called", models.String(), w))
	}

	var recent strings.Builder
	if !m.detailLoaded || len(u.Recent) == 0 {
		recent.WriteString(dimStyle.Render("none") + "\n")
	}
	for _, r := range u.Recent {
		modelName := r.Model
		if modelName == "" {
			modelName = "—"
		}
		status := strconv.Itoa(r.Status)
		st := okStyle
		if r.Status >= 400 {
			st = badStyle
		}
		line := fmtTime(r.Time) + "  " + st.Render(status) + "  " + fmt.Sprintf("%dms", r.LatencyMS) + "  " + r.IP + "  " + modelName
		if r.BlockedCode != "" {
			line += "  " + badStyle.Render(r.BlockedCode)
		}
		recent.WriteString(line + "\n")
		cost := "—"
		if r.CostMicro != nil {
			cost = usd(*r.CostMicro)
			if r.CostEstimated {
				cost += " estimated"
			}
		}
		fmt.Fprintf(&recent, "  %s  in %d · out %d  %s\n", dimStyle.Render(r.Operation), r.TokensIn, r.TokensOut, cost)
	}
	panels = append(panels, panel("recent requests · newest first", recent.String(), w))

	var dets strings.Builder
	if len(m.detailDets) == 0 {
		dets.WriteString(okStyle.Render("none") + dimStyle.Render(" · no rule has fired on this key") + "\n")
	}
	for _, d := range m.detailDets {
		dets.WriteString(fmtTime(d.Time) + "  " + severityStyle(d.Severity).Render(fit(d.Severity, 8)) + "  " + d.Rule + "\n")
	}
	panels = append(panels, panel("detections · rules that fired", dets.String(), w))
	return strings.Join(panels, "\n") + "\n"
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

// pair draws two panels side by side with equal heights.
func pair(lt, lc, rt, rc string, width int) string {
	lw := width / 2
	n := max(lineCount(strings.TrimSuffix(lc, "\n")), lineCount(strings.TrimSuffix(rc, "\n")))
	pad := func(c string) string {
		c = strings.TrimSuffix(c, "\n")
		return c + strings.Repeat("\n", n-lineCount(c)+1)
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, panel(lt, pad(lc), lw), panel(rt, pad(rc), width-lw))
}

func usageSummary(u KeyUsage) string {
	var b strings.Builder
	b.WriteString(kv("requests", strconv.Itoa(u.Requests)+" total"))
	if !u.LastSeen.IsZero() {
		b.WriteString(kv("last seen", fmtTime(u.LastSeen)))
	}
	tokens := fmt.Sprintf("in %d · out %d", u.TokensIn, u.TokensOut)
	if u.Cached > 0 {
		tokens += fmt.Sprintf(" · cached %d", u.Cached)
	}
	if u.CacheWrite > 0 {
		tokens += fmt.Sprintf(" · cache write %d", u.CacheWrite)
	}
	b.WriteString(kv("tokens", tokens))
	cost := "— (model not in the price table)"
	if u.Priced > 0 {
		cost = usd(u.CostMicro)
		if u.Estimated > 0 {
			cost += " (some estimated)"
		}
	}
	b.WriteString(kv("cost", cost))
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
	"Requests per minute. Leave empty for no limit.",
	"Dollars per UTC day, such as 1.50. Leave empty for no cap.",
	"Dollars per UTC month, such as 20. Leave empty for no cap.",
}

func (m model) renderPolicy() string {
	return m.form("policy · "+m.policyName, []string{
		fieldLine(m.polField == 0, "mode", policyModes[m.polMode], true),
		fieldLine(m.polField == 1, "rpm", m.rpmInput.View(), false),
		fieldLine(m.polField == 2, "daily $", m.dailyInput.View(), false),
		fieldLine(m.polField == 3, "monthly $", m.monthlyInput.View(), false),
	}, policyHints[m.polField]+"\nPath, model, and network allowlists on this key are kept.")
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

func todayLine(k Key) string {
	s := usd(k.SpendToday)
	if k.SpendOpen > 0 {
		s += " (+" + usd(k.SpendOpen) + ")"
	}
	return s
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
