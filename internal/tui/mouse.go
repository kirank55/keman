package tui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var buttonStyle = lipgloss.NewStyle().Padding(0, 1).
	Foreground(lipgloss.AdaptiveColor{Light: "0", Dark: "0"}).
	Background(accent).Bold(true)
var buttonQuietStyle = lipgloss.NewStyle().Padding(0, 1).Background(selBg)

// button is a clickable label that does what pressing key would.
type button struct {
	label   string
	key     tea.KeyType
	primary bool
}

// overlayButtons are the click targets for the confirmation dialogs. Every
// button replays a key, so the mouse can never do more than the keyboard.
func (m model) overlayButtons() []button {
	switch m.overlay {
	case overlayRevoke:
		return []button{{"Revoke", tea.KeyEnter, true}, {"Cancel", tea.KeyEsc, false}}
	case overlayRotate:
		return []button{{"Rotate", tea.KeyEnter, true}, {"Cancel", tea.KeyEsc, false}}
	case overlayConfirm:
		return []button{{"Switch to auto_disable", tea.KeyEnter, true}, {"Back", tea.KeyEsc, false}}
	}
	return nil
}

// buttonRow renders the overlay buttons on one line, two spaces apart.
func (m model) buttonRow() string {
	var parts []string
	for _, b := range m.overlayButtons() {
		st := buttonQuietStyle
		if b.primary {
			st = buttonStyle
		}
		parts = append(parts, st.Render(b.label))
	}
	return strings.Join(parts, "  ")
}

// buttonAt returns the overlay button under column x, if any.
func (m model) buttonAt(x int) (button, bool) {
	pos := 0
	for _, b := range m.overlayButtons() {
		w := lipgloss.Width(b.label) + 2
		if x >= pos && x < pos+w {
			return b, true
		}
		pos += w + 2
	}
	return button{}, false
}

// tabAt returns the screen whose header label is under column x.
func (m model) tabAt(x int) (screen, bool) {
	names := []string{"1 keys", "2 detections", "3 audit", "4 setup"}
	total := 2 * (len(names) - 1)
	for _, n := range names {
		total += lipgloss.Width(n)
	}
	host := m.base
	if host == "" {
		host = "admin API"
	}
	pos := m.width - total
	if pos-lipgloss.Width("keman · "+host) < 2 {
		// header() drops the title when the tabs do not fit beside it.
		pos = 0
	}
	for i, n := range names {
		w := lipgloss.Width(n)
		if x >= pos && x < pos+w {
			return screen(i), true
		}
		pos += w + 2
	}
	return 0, false
}

// listTop is the screen row of the first table row on the current screen.
func (m model) listTop() int {
	top := 2 // header line, then the table's own header
	top += strings.Count(m.filterBanner(), "\n")
	if m.screen == screenKeys {
		top += strings.Count(m.exposureBanner(), "\n")
	}
	return top
}

func (m model) onMouse(msg tea.MouseMsg) (model, tea.Cmd) {
	if msg.Action != tea.MouseActionPress || msg.Button != tea.MouseButtonLeft {
		return m, nil
	}
	if m.filtering {
		return m, nil
	}
	if b := m.overlayButtons(); len(b) > 0 {
		body := strings.TrimSuffix(m.renderBody(), "\n")
		if msg.Y != lineCount(body) {
			return m, nil
		}
		if hit, ok := m.buttonAt(msg.X); ok {
			next, cmd := m.Update(tea.KeyMsg{Type: hit.key})
			return next.(model), cmd
		}
		return m, nil
	}
	if m.overlay != overlayNone {
		return m, nil
	}
	if msg.Y == 0 {
		if s, ok := m.tabAt(msg.X); ok && s != m.screen {
			return m.switchScreen(s)
		}
		return m, nil
	}
	n := m.listLen()
	start, end := m.span(n)
	row := start + msg.Y - m.listTop()
	if msg.Y < m.listTop() || row >= end {
		return m, nil
	}
	if row == m.cursor {
		return m.onScreen(tea.KeyMsg{Type: tea.KeyEnter})
	}
	m.cursor = row
	return m, nil
}
