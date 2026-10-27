// Package redact keeps virtual keys and configured secrets out of logs.
package redact

import (
	"context"
	"log/slog"
	"regexp"
	"strings"
	"sync"
)

var virtualKey = regexp.MustCompile(`kmn_[0-9A-Za-z]{8}_[0-9A-Za-z]+`)

// Secrets is a set of extra strings that must never be logged.
type Secrets struct {
	mu    sync.RWMutex
	items []string
}

func (s *Secrets) Add(secret string) {
	if len(secret) < 4 {
		return
	}
	s.mu.Lock()
	s.items = append(s.items, secret)
	s.mu.Unlock()
}

func (s *Secrets) scrub(msg string) string {
	msg = virtualKey.ReplaceAllString(msg, "kmn_[redacted]")
	if s == nil {
		return msg
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, item := range s.items {
		if item != "" {
			msg = strings.ReplaceAll(msg, item, "[redacted]")
		}
	}
	return msg
}

// Handler wraps a slog handler and scrubs messages and string attributes.
type Handler struct {
	next    slog.Handler
	secrets *Secrets
	group   string
	attrs   []slog.Attr
}

func New(next slog.Handler, secrets *Secrets) *Handler {
	if secrets == nil {
		secrets = &Secrets{}
	}
	return &Handler{next: next, secrets: secrets}
}

func (h *Handler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	nr := slog.NewRecord(r.Time, r.Level, h.secrets.scrub(r.Message), r.PC)
	r.Attrs(func(a slog.Attr) bool {
		nr.AddAttrs(h.scrubAttr(a))
		return true
	})
	return h.next.Handle(ctx, nr)
}

func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := *h
	out.next = h.next.WithAttrs(h.scrubAttrs(attrs))
	return &out
}

func (h *Handler) WithGroup(name string) slog.Handler {
	out := *h
	out.next = h.next.WithGroup(name)
	return &out
}

func (h *Handler) scrubAttrs(attrs []slog.Attr) []slog.Attr {
	out := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		out[i] = h.scrubAttr(a)
	}
	return out
}

func (h *Handler) scrubAttr(a slog.Attr) slog.Attr {
	switch a.Value.Kind() {
	case slog.KindString:
		a.Value = slog.StringValue(h.secrets.scrub(a.Value.String()))
	case slog.KindGroup:
		gs := a.Value.Group()
		a.Value = slog.GroupValue(h.scrubAttrs(gs)...)
	}
	return a
}
