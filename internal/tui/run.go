package tui

import (
	"context"
	"errors"
	"io"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"
)

// ErrNotTerminal is returned when stdout is not a terminal.
var ErrNotTerminal = errors.New("keman needs a terminal")

// IsTerminal reports whether w is an interactive terminal.
func IsTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok || f == nil {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}

// Run starts the full-screen UI. It returns ErrNotTerminal instead of
// drawing when stdout is a pipe.
func Run(ctx context.Context, api API, base string, in io.Reader, out io.Writer) error {
	if !IsTerminal(out) {
		return ErrNotTerminal
	}
	m := newModel(ctx, api, base)
	m.getenv = os.Getenv
	if gate, ok := api.(adminGate); ok && !gate.HasAdminToken() {
		m.overlay = overlayAdmin
		m.loading = false
		m.setToken = gate.SetAdminToken
	}
	opts := []tea.ProgramOption{tea.WithAltScreen(), tea.WithMouseCellMotion(), tea.WithOutput(out)}
	if in != nil {
		opts = append(opts, tea.WithInput(in))
	}
	if ctx != nil {
		opts = append(opts, tea.WithContext(ctx))
	}
	_, err := tea.NewProgram(m, opts...).Run()
	return err
}
