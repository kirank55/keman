// Package alert delivers detections to Slack and signed webhooks.
package alert

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kirank55/keman/internal/model"
)

// Sign is HMAC-SHA256 over "<unix>.<body>".
func Sign(secret string, ts int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(ts, 10)))
	mac.Write([]byte("."))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// HeaderValue is the X-Keman-Signature header.
func HeaderValue(secret string, ts int64, body []byte) string {
	return "t=" + strconv.FormatInt(ts, 10) + ",v1=" + Sign(secret, ts, body)
}

type Sender struct {
	Client       *http.Client
	Now          func() time.Time
	Destinations func() []model.AlertDestination
}

func (s *Sender) Send(ctx context.Context, a model.Alert) error {
	if s.Destinations == nil {
		return nil
	}
	if a.Summary == "" {
		a.Summary = Summary(a)
	}
	body, err := json.Marshal(a)
	if err != nil {
		return err
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	client := s.Client
	if client == nil {
		client = &http.Client{Timeout: 4 * time.Second}
	}
	var errs []string
	for _, d := range s.Destinations() {
		var req *http.Request
		switch d.Kind {
		case "slack":
			text := slackText(a)
			payload, _ := json.Marshal(map[string]string{"text": text})
			req, err = http.NewRequestWithContext(ctx, http.MethodPost, d.URL, bytes.NewReader(payload))
			if err != nil {
				errs = append(errs, err.Error())
				continue
			}
			req.Header.Set("Content-Type", "application/json")
		case "webhook":
			ts := now().Unix()
			req, err = http.NewRequestWithContext(ctx, http.MethodPost, d.URL, bytes.NewReader(body))
			if err != nil {
				errs = append(errs, err.Error())
				continue
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Keman-Signature", HeaderValue(d.Secret, ts, body))
		default:
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			errs = append(errs, fmt.Sprintf("%s returned %d", d.Kind, resp.StatusCode))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// Summary is one line: what fired, on which key, and where the request came from.
func Summary(a model.Alert) string {
	key := a.KeyID
	if a.KeyName != "" {
		key = a.KeyName + " (" + a.KeyID + ")"
	}
	s := a.Rule + " on virtual key " + key
	if where := Where(a.Observed); where != "" {
		s += " from " + where
	}
	if op, _ := a.Observed["operation"].(string); op != "" {
		s += " calling " + op
	}
	return s
}

// Where is the client address with its country and ASN when known.
func Where(observed map[string]any) string {
	ip, _ := observed["ip"].(string)
	if ip == "" {
		return ""
	}
	var extra []string
	if c, _ := observed["country"].(string); c != "" {
		extra = append(extra, c)
	}
	switch n := observed["asn"].(type) {
	case int:
		if n != 0 {
			extra = append(extra, "AS"+strconv.Itoa(n))
		}
	case float64:
		if n != 0 {
			extra = append(extra, "AS"+strconv.FormatInt(int64(n), 10))
		}
	}
	if len(extra) == 0 {
		return ip
	}
	return ip + " (" + strings.Join(extra, ", ") + ")"
}

func slackText(a model.Alert) string {
	var b strings.Builder
	summary := a.Summary
	if summary == "" {
		summary = Summary(a)
	}
	fmt.Fprintf(&b, "[%s] %s\n", a.Severity, summary)
	if len(a.Evidence) > 0 {
		ev, _ := json.Marshal(a.Evidence)
		b.WriteString("evidence: ")
		b.Write(ev)
		b.WriteByte('\n')
	}
	if len(a.Actions) > 0 {
		b.WriteString("what to do:\n")
		for _, act := range a.Actions {
			b.WriteString("  " + act.When + "\n")
			if act.Command != "" {
				b.WriteString("    " + act.Command + "\n")
			}
		}
		return b.String()
	}
	b.WriteString("commands:\n")
	for _, c := range a.Commands {
		b.WriteString("  ")
		b.WriteString(c)
		b.WriteByte('\n')
	}
	return b.String()
}
