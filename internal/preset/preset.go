// Package preset is the registry of platforms Keman knows how to front.
// A preset fills in an upstream (profile, host, TLS, path allowlist) and the
// default auth for its credentials. Every field can still be overridden.
package preset

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kirank55/keman/internal/model"
	"github.com/kirank55/keman/internal/profile"
)

// Preset describes one platform.
type Preset struct {
	Name  string
	Title string
	// Profile decides token and spend tracking: openai, anthropic or generic.
	Profile string
	Host    string
	Port    int
	TLS     bool
	// Paths is the allowlist. Empty uses the profile's built-in list.
	Paths []string
	// InjectUsage sets stream_options.include_usage on OpenAI-style streams.
	// Off for servers that reject the field.
	InjectUsage bool
	// Auth is model.AuthHeader or model.AuthBasic.
	Auth   string
	Header string
	// UserPass means a Basic credential without a username takes the secret
	// as user:password.
	UserPass bool
	// Env is the variable an SDK for this platform reads the key from.
	Env string
	// BasePath is appended to the Keman URL to make the SDK base URL.
	BasePath string
}

const bearer = "Authorization: Bearer {key}"

// all is ordered for display: the LLM platforms, then other APIs.
var all = []Preset{
	{Name: "openai", Title: "OpenAI", Profile: profile.OpenAI, Host: "api.openai.com", InjectUsage: true, Env: "OPENAI_API_KEY", BasePath: "/v1"},
	{Name: "anthropic", Title: "Anthropic", Profile: profile.Anthropic, Host: "api.anthropic.com", Header: "x-api-key: {key}", Env: "ANTHROPIC_API_KEY"},
	{Name: "openrouter", Title: "OpenRouter", Profile: profile.OpenAI, Host: "openrouter.ai", InjectUsage: true, Env: "OPENROUTER_API_KEY", BasePath: "/api/v1", Paths: []string{
		"POST /api/v1/chat/completions",
		"GET /api/v1/models",
		"GET /api/v1/models/*",
	}},
	{Name: "gemini", Title: "Google Gemini (OpenAI-compatible)", Profile: profile.OpenAI, Host: "generativelanguage.googleapis.com", InjectUsage: true, Env: "GEMINI_API_KEY", BasePath: "/v1beta/openai", Paths: []string{
		"POST /v1beta/openai/chat/completions",
		"POST /v1beta/openai/embeddings",
		"GET /v1beta/openai/models",
		"GET /v1beta/openai/models/**",
	}},
	{Name: "groq", Title: "Groq", Profile: profile.OpenAI, Host: "api.groq.com", InjectUsage: true, Env: "GROQ_API_KEY", BasePath: "/openai/v1", Paths: []string{
		"POST /openai/v1/chat/completions",
		"POST /openai/v1/responses",
		"POST /openai/v1/audio/transcriptions",
		"POST /openai/v1/audio/translations",
		"GET /openai/v1/models",
		"GET /openai/v1/models/**",
	}},
	{Name: "mistral", Title: "Mistral", Profile: profile.OpenAI, Host: "api.mistral.ai", Env: "MISTRAL_API_KEY", BasePath: "/v1", Paths: []string{
		"POST /v1/chat/completions",
		"POST /v1/fim/completions",
		"POST /v1/embeddings",
		"GET /v1/models",
		"GET /v1/models/*",
	}},
	{Name: "deepseek", Title: "DeepSeek", Profile: profile.OpenAI, Host: "api.deepseek.com", InjectUsage: true, Env: "DEEPSEEK_API_KEY", Paths: []string{
		"POST /chat/completions",
		"POST /v1/chat/completions",
		"GET /models",
		"GET /v1/models",
	}},
	{Name: "xai", Title: "xAI (Grok)", Profile: profile.OpenAI, Host: "api.x.ai", InjectUsage: true, Env: "XAI_API_KEY", BasePath: "/v1", Paths: []string{
		"POST /v1/chat/completions",
		"POST /v1/responses",
		"GET /v1/responses/*",
		"GET /v1/models",
		"GET /v1/models/*",
	}},
	{Name: "together", Title: "Together AI", Profile: profile.OpenAI, Host: "api.together.xyz", InjectUsage: true, Env: "TOGETHER_API_KEY", BasePath: "/v1", Paths: []string{
		"POST /v1/chat/completions",
		"POST /v1/completions",
		"POST /v1/embeddings",
		"GET /v1/models",
	}},
	{Name: "fireworks", Title: "Fireworks AI", Profile: profile.OpenAI, Host: "api.fireworks.ai", InjectUsage: true, Env: "FIREWORKS_API_KEY", BasePath: "/inference/v1", Paths: []string{
		"POST /inference/v1/chat/completions",
		"POST /inference/v1/completions",
		"POST /inference/v1/embeddings",
	}},
	{Name: "cerebras", Title: "Cerebras", Profile: profile.OpenAI, Host: "api.cerebras.ai", Env: "CEREBRAS_API_KEY", BasePath: "/v1", Paths: []string{
		"POST /v1/chat/completions",
		"POST /v1/completions",
		"GET /v1/models",
		"GET /v1/models/*",
	}},

	{Name: "stripe", Title: "Stripe", Profile: profile.Generic, Host: "api.stripe.com", Env: "STRIPE_SECRET_KEY", Paths: []string{
		"POST /v1/payment_intents",
		"GET /v1/payment_intents/*",
		"POST /v1/payment_intents/*",
		"POST /v1/payment_intents/*/confirm",
		"POST /v1/payment_intents/*/cancel",
		"POST /v1/checkout/sessions",
		"GET /v1/checkout/sessions/*",
		"POST /v1/customers",
		"GET /v1/customers",
		"GET /v1/customers/*",
		"POST /v1/customers/*",
		"GET /v1/charges",
		"GET /v1/charges/*",
		"GET /v1/prices",
		"GET /v1/products",
		"GET /v1/subscriptions",
		"GET /v1/subscriptions/*",
		"GET /v1/invoices",
		"GET /v1/invoices/*",
	}},
	{Name: "github", Title: "GitHub", Profile: profile.Generic, Host: "api.github.com", Env: "GITHUB_TOKEN", Paths: []string{
		"GET /user",
		"GET /user/repos",
		"GET /repos/**",
		"GET /orgs/*/repos",
		"GET /search/**",
		"POST /repos/*/*/issues",
		"PATCH /repos/*/*/issues/*",
		"POST /repos/*/*/issues/*/comments",
		"POST /repos/*/*/pulls",
		"POST /repos/*/*/pulls/*/reviews",
	}},
	{Name: "slack", Title: "Slack", Profile: profile.Generic, Host: "slack.com", Env: "SLACK_BOT_TOKEN", BasePath: "/api", Paths: []string{
		"POST /api/auth.test",
		"POST /api/chat.postMessage",
		"POST /api/chat.postEphemeral",
		"POST /api/chat.update",
		"POST /api/reactions.add",
		"* /api/conversations.list",
		"* /api/conversations.history",
		"* /api/conversations.replies",
		"* /api/users.info",
		"POST /api/files.getUploadURLExternal",
		"POST /api/files.completeUploadExternal",
	}},
	{Name: "twilio", Title: "Twilio", Profile: profile.Generic, Host: "api.twilio.com", Auth: model.AuthBasic, UserPass: true, Env: "TWILIO_AUTH_TOKEN", Paths: []string{
		"POST /2010-04-01/Accounts/*/Messages.json",
		"GET /2010-04-01/Accounts/*/Messages.json",
		"GET /2010-04-01/Accounts/*/Messages/*",
		"POST /2010-04-01/Accounts/*/Calls.json",
		"GET /2010-04-01/Accounts/*/Calls/*",
	}},
	{Name: "sendgrid", Title: "SendGrid", Profile: profile.Generic, Host: "api.sendgrid.com", Env: "SENDGRID_API_KEY", Paths: []string{
		"POST /v3/mail/send",
		"GET /v3/templates",
		"GET /v3/templates/*",
	}},
	{Name: "resend", Title: "Resend", Profile: profile.Generic, Host: "api.resend.com", Env: "RESEND_API_KEY", Paths: []string{
		"POST /emails",
		"POST /emails/batch",
		"GET /emails/*",
	}},
	{Name: "postmark", Title: "Postmark", Profile: profile.Generic, Host: "api.postmarkapp.com", Header: "X-Postmark-Server-Token: {key}", Env: "POSTMARK_SERVER_TOKEN", Paths: []string{
		"POST /email",
		"POST /email/batch",
		"POST /email/withTemplate",
		"POST /email/batchWithTemplates",
		"GET /messages/outbound",
		"GET /messages/outbound/*/details",
	}},
	{Name: "cloudflare", Title: "Cloudflare", Profile: profile.Generic, Host: "api.cloudflare.com", Env: "CLOUDFLARE_API_TOKEN", BasePath: "/client/v4", Paths: []string{
		"GET /client/v4/user/tokens/verify",
		"GET /client/v4/zones",
		"GET /client/v4/zones/*",
		"GET /client/v4/zones/*/dns_records",
		"GET /client/v4/zones/*/dns_records/*",
		"POST /client/v4/zones/*/dns_records",
		"PATCH /client/v4/zones/*/dns_records/*",
		"DELETE /client/v4/zones/*/dns_records/*",
		"POST /client/v4/zones/*/purge_cache",
	}},
	{Name: "linear", Title: "Linear", Profile: profile.Generic, Host: "api.linear.app", Header: "Authorization: {key}", Env: "LINEAR_API_KEY", Paths: []string{
		"POST /graphql",
	}},
	{Name: "notion", Title: "Notion", Profile: profile.Generic, Host: "api.notion.com", Env: "NOTION_TOKEN", Paths: []string{
		"GET /v1/users/me",
		"POST /v1/search",
		"POST /v1/pages",
		"GET /v1/pages/*",
		"PATCH /v1/pages/*",
		"GET /v1/databases/*",
		"POST /v1/databases/*/query",
		"GET /v1/data_sources/*",
		"POST /v1/data_sources/*/query",
		"GET /v1/blocks/*",
		"GET /v1/blocks/*/children",
		"PATCH /v1/blocks/*/children",
	}},
}

var byName = func() map[string]Preset {
	m := make(map[string]Preset, len(all))
	for i := range all {
		p := &all[i]
		if p.Port == 0 {
			p.Port = 443
			p.TLS = true
		}
		if p.Auth == "" {
			p.Auth = model.AuthHeader
		}
		if p.Auth == model.AuthHeader && p.Header == "" {
			p.Header = bearer
		}
		if _, dup := m[p.Name]; dup {
			panic("duplicate preset " + p.Name)
		}
		m[p.Name] = *p
	}
	return m
}()

// All returns every preset in display order.
func All() []Preset {
	out := make([]Preset, len(all))
	copy(out, all)
	return out
}

func Get(name string) (Preset, bool) {
	p, ok := byName[strings.ToLower(strings.TrimSpace(name))]
	return p, ok
}

// Names lists preset names, sorted.
func Names() []string {
	out := make([]string, 0, len(byName))
	for n := range byName {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// DefaultHeader is the credential header for an upstream with no preset.
func DefaultHeader(prof string) string {
	if prof == profile.Anthropic {
		return "x-api-key: {key}"
	}
	return bearer
}

// SDKBaseURL is what an app sets as its base URL to reach p through Keman.
func (p Preset) SDKBaseURL(keman string) string {
	return strings.TrimRight(keman, "/") + p.BasePath
}

// Tracking says what Keman measures for this platform.
func (p Preset) Tracking() string {
	if profile.IsLLM(p.Profile) {
		return "tokens and spend"
	}
	return "requests"
}

// TableStart and TableEnd mark the generated platform table in README.md.
const (
	TableStart = "<!-- presets:start -->"
	TableEnd   = "<!-- presets:end -->"
)

// Markdown renders the README table of supported platforms.
func Markdown() string {
	var b strings.Builder
	b.WriteString("| Platform | Preset | Tracks | App base URL |\n")
	b.WriteString("| --- | --- | --- | --- |\n")
	for _, p := range all {
		fmt.Fprintf(&b, "| %s | `%s` | %s | `%s` |\n", p.Title, p.Name, p.Tracking(), p.SDKBaseURL("http://127.0.0.1:8080"))
	}
	return b.String()
}
