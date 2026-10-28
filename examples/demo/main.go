// Command demo supports scripts/demo.sh, which seeds a Keman install with
// realistic keys, traffic and detections for screenshots and live demos.
//
//	demo geoip DIR                    write country.mmdb and asn.mmdb for the demo networks
//	demo upstream ADDR                answer like OpenAI, Anthropic and Stripe
//	demo sink ADDR FILE               append every alert POST to FILE as JSON lines
//	demo traffic -proxy URL -key-file F -ip IP [-n N] [...]
//	demo history -db FILE -geoip DIR [-days 8]
//
// history backfills a week of normal use while the server is stopped. It
// runs the events through the real detection engine with a fake clock, so
// the server starts with learned baselines, and stores events, baselines
// and spend the way the server would.
//
// Every address is in a documentation range (RFC 5737) and every ASN is in
// the documentation range (RFC 5398), so the demo never names a real network.
package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kirank55/keman/internal/clock"
	"github.com/kirank55/keman/internal/detect"
	"github.com/kirank55/keman/internal/geoip"
	"github.com/kirank55/keman/internal/model"
	"github.com/kirank55/keman/internal/price"
	"github.com/kirank55/keman/internal/state"
	"github.com/kirank55/keman/internal/store"
)

// network is one demo range and what GeoIP says about it.
type network struct {
	cidr    string
	country string
	asn     uint32
	org     string
}

var networks = []network{
	{"203.0.113.0/25", "US", 64500, "Example Office ISP"},
	{"198.51.100.0/25", "US", 64501, "Example CI Cloud"},
	{"192.0.2.0/25", "DE", 64502, "Example Hosting EU"},
	{"203.0.113.128/25", "BR", 64510, "Example Residential BR"},
	{"192.0.2.128/25", "NL", 64511, "Example VPS NL"},
	{"198.51.100.128/25", "SG", 64512, "Example Cloud SG"},
}

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		log.Fatal("usage: demo geoip|upstream|sink|traffic|history ...")
	}
	args := os.Args[2:]
	switch os.Args[1] {
	case "geoip":
		if len(args) != 1 {
			log.Fatal("usage: demo geoip DIR")
		}
		if err := writeGeoIP(args[0]); err != nil {
			log.Fatal(err)
		}
	case "upstream":
		if len(args) != 1 {
			log.Fatal("usage: demo upstream ADDR")
		}
		log.Fatal(http.ListenAndServe(args[0], upstream()))
	case "sink":
		if len(args) != 2 {
			log.Fatal("usage: demo sink ADDR FILE")
		}
		log.Fatal(http.ListenAndServe(args[0], sink(args[1])))
	case "traffic":
		if err := traffic(args); err != nil {
			log.Fatal(err)
		}
	case "history":
		if err := history(args); err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatalf("unknown command %q", os.Args[1])
	}
}

// ---- GeoIP ----------------------------------------------------------------

func writeGeoIP(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	country := make([]map[string]any, len(networks))
	asn := make([]map[string]any, len(networks))
	for i, n := range networks {
		country[i] = map[string]any{"country": map[string]any{"iso_code": n.country}}
		asn[i] = map[string]any{"autonomous_system_number": n.asn, "autonomous_system_organization": n.org}
	}
	if err := writeMMDB(filepath.Join(dir, "country.mmdb"), "Keman-Demo-Country", country); err != nil {
		return err
	}
	return writeMMDB(filepath.Join(dir, "asn.mmdb"), "Keman-Demo-ASN", asn)
}

// writeMMDB writes an IPv4 MaxMind DB with 24-bit records: a binary trie
// over address bits, a 16-byte separator, the data section, then metadata.
// Networks must not overlap.
func writeMMDB(path, dbType string, records []map[string]any) error {
	const (
		empty = -1
		data  = -2
	)
	type rec struct{ kind, v int } // kind: node index, empty, or data (v = offset)
	type node struct{ r [2]rec }
	nodes := []node{{r: [2]rec{{empty, 0}, {empty, 0}}}}
	var section bytes.Buffer
	for i, n := range networks {
		_, ipnet, err := net.ParseCIDR(n.cidr)
		if err != nil {
			return err
		}
		ones, _ := ipnet.Mask.Size()
		ip := binary.BigEndian.Uint32(ipnet.IP.To4())
		off := section.Len()
		encode(&section, records[i])
		cur := 0
		for bit := 0; bit < ones; bit++ {
			side := int(ip>>(31-bit)) & 1
			if bit == ones-1 {
				nodes[cur].r[side] = rec{data, off}
				break
			}
			next := nodes[cur].r[side]
			if next.kind == data {
				return fmt.Errorf("%s overlaps another network", n.cidr)
			}
			if next.kind == empty {
				nodes = append(nodes, node{r: [2]rec{{empty, 0}, {empty, 0}}})
				next = rec{len(nodes) - 1, 0}
				nodes[cur].r[side] = next
			}
			cur = next.kind
		}
	}
	count := len(nodes)
	var out bytes.Buffer
	for _, n := range nodes {
		for _, r := range n.r {
			v := 0
			switch r.kind {
			case empty:
				v = count
			case data:
				v = count + 16 + r.v
			default:
				v = r.kind
			}
			out.Write([]byte{byte(v >> 16), byte(v >> 8), byte(v)})
		}
	}
	out.Write(make([]byte, 16))
	out.Write(section.Bytes())
	out.WriteString("\xAB\xCD\xEFMaxMind.com")
	encode(&out, map[string]any{
		"binary_format_major_version": uint16(2),
		"binary_format_minor_version": uint16(0),
		"build_epoch":                 uint64(time.Now().Unix()),
		"database_type":               dbType,
		"description":                 map[string]any{"en": "Keman demo data for documentation address ranges"},
		"ip_version":                  uint16(4),
		"languages":                   []any{"en"},
		"node_count":                  uint32(count),
		"record_size":                 uint16(24),
	})
	return os.WriteFile(path, out.Bytes(), 0o644)
}

// encode writes one value in the MaxMind DB data format.
func encode(b *bytes.Buffer, v any) {
	switch x := v.(type) {
	case string:
		header(b, 2, len(x))
		b.WriteString(x)
	case uint16:
		uintBytes(b, 5, uint64(x))
	case uint32:
		uintBytes(b, 6, uint64(x))
	case uint64:
		uintBytes(b, 9, x)
	case map[string]any:
		header(b, 7, len(x))
		for k, val := range x {
			encode(b, k)
			encode(b, val)
		}
	case []any:
		header(b, 11, len(x))
		for _, val := range x {
			encode(b, val)
		}
	default:
		panic(fmt.Sprintf("mmdb: unsupported %T", v))
	}
}

func uintBytes(b *bytes.Buffer, typ int, v uint64) {
	var raw []byte
	for v > 0 {
		raw = append([]byte{byte(v)}, raw...)
		v >>= 8
	}
	header(b, typ, len(raw))
	b.Write(raw)
}

// header writes the control byte: 3 type bits and 5 size bits. Types above
// 7 are "extended": type bits zero, then a byte holding type-7. Sizes of 29
// and up continue in the bytes after that.
func header(b *bytes.Buffer, typ, size int) {
	sizeBits, extra := size, []byte(nil)
	switch {
	case size >= 285:
		panic("mmdb: size too large for the demo writer")
	case size >= 29:
		sizeBits, extra = 29, []byte{byte(size - 29)}
	}
	if typ <= 7 {
		b.WriteByte(byte(typ<<5 | sizeBits))
	} else {
		b.WriteByte(byte(sizeBits))
		b.WriteByte(byte(typ - 7))
	}
	b.Write(extra)
}

// ---- upstream -------------------------------------------------------------

// A real key containing "revoked" is refused, as if it was rotated at the
// provider, so the demo can show an upstream auth-error burst.
func upstream() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Authorization"), "revoked") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":{"message":"Incorrect API key provided.","type":"invalid_request_error","code":"invalid_api_key"}}`)
			return
		}
		var req struct {
			Model     string `json:"model"`
			Stream    bool   `json:"stream"`
			MaxTokens int    `json:"max_tokens"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		in, out := tokens(req.MaxTokens)
		usage := fmt.Sprintf(`{"prompt_tokens":%d,"completion_tokens":%d,"total_tokens":%d}`, in, out, in+out)
		if req.Stream {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprintf(w, "data: {\"id\":\"chatcmpl-demo\",\"object\":\"chat.completion.chunk\",\"model\":%q,\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Hello from the demo upstream.\"},\"finish_reason\":null}]}\n\n", req.Model)
			fmt.Fprintf(w, "data: {\"id\":\"chatcmpl-demo\",\"object\":\"chat.completion.chunk\",\"model\":%q,\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":%s}\n\n", req.Model, usage)
			_, _ = io.WriteString(w, "data: [DONE]\n\n")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":"chatcmpl-demo","object":"chat.completion","model":%q,"choices":[{"index":0,"message":{"role":"assistant","content":"Hello from the demo upstream."},"finish_reason":"stop"}],"usage":%s}`, req.Model, usage)
	})
	mux.HandleFunc("/v1/messages", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("X-Api-Key"), "revoked") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}`)
			return
		}
		var req struct {
			Model     string `json:"model"`
			MaxTokens int    `json:"max_tokens"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		in, out := tokens(req.MaxTokens)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":"msg_demo","type":"message","role":"assistant","model":%q,"content":[{"type":"text","text":"Hello from the demo upstream."}],"stop_reason":"end_turn","usage":{"input_tokens":%d,"output_tokens":%d}}`, req.Model, in, out)
	})
	mux.HandleFunc("/v1/charges", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":"ch_demo%06d","object":"charge","amount":2000,"currency":"usd","status":"succeeded"}`, rand.Intn(1000000))
	})
	mux.HandleFunc("/v1/customers/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":%q,"object":"customer"}`, strings.TrimPrefix(r.URL.Path, "/v1/customers/"))
	})
	return mux
}

// tokens returns plausible input and output counts for one chat turn. A
// large max_tokens stands for someone draining the key with long prompts.
func tokens(maxTokens int) (int, int) {
	if maxTokens >= 8000 {
		return 40000 + rand.Intn(30000), maxTokens/4 + rand.Intn(maxTokens/4)
	}
	return 600 + rand.Intn(2400), 80 + rand.Intn(700)
}

// ---- alert sink -----------------------------------------------------------

func sink(file string) http.Handler {
	var mu sync.Mutex
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		line, _ := json.Marshal(map[string]any{
			"path":      r.URL.Path,
			"signature": r.Header.Get("X-Keman-Signature"),
			"body":      json.RawMessage(body),
		})
		mu.Lock()
		defer mu.Unlock()
		f, err := os.OpenFile(file, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer f.Close()
		_, _ = f.Write(append(line, '\n'))
		_, _ = io.WriteString(w, "ok")
	})
}

// ---- traffic --------------------------------------------------------------

func traffic(args []string) error {
	fs := flag.NewFlagSet("traffic", flag.ContinueOnError)
	proxy := fs.String("proxy", "http://127.0.0.1:8080", "Keman proxy URL")
	keyFile := fs.String("key-file", "", "file holding the virtual key")
	ip := fs.String("ip", "", "client address, sent as X-Forwarded-For")
	n := fs.Int("n", 1, "requests to send")
	conc := fs.Int("c", 8, "concurrent requests")
	prof := fs.String("profile", "openai", "openai, anthropic or generic")
	model := fs.String("model", "gpt-4o-mini", "model for LLM profiles")
	maxTokens := fs.Int("max-tokens", 1024, "max_tokens for LLM profiles")
	method := fs.String("method", "", "HTTP method (default POST, or GET for generic)")
	path := fs.String("path", "", "request path (default per profile)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	raw, err := os.ReadFile(*keyFile)
	if err != nil {
		return err
	}
	key := strings.TrimSpace(string(raw))
	m, p, body := *method, *path, ""
	switch *prof {
	case "openai":
		if p == "" {
			p = "/v1/chat/completions"
		}
		body = fmt.Sprintf(`{"model":%q,"max_tokens":%d,"messages":[{"role":"user","content":"Summarize this ticket."}]}`, *model, *maxTokens)
	case "anthropic":
		if p == "" {
			p = "/v1/messages"
		}
		body = fmt.Sprintf(`{"model":%q,"max_tokens":%d,"messages":[{"role":"user","content":"Summarize this ticket."}]}`, *model, *maxTokens)
	case "generic":
		if p == "" {
			p = "/v1/charges"
		}
		if m == "" && p == "/v1/charges" {
			m = http.MethodPost
			body = `{"amount":2000,"currency":"usd"}`
		}
	default:
		return fmt.Errorf("unknown profile %q", *prof)
	}
	if m == "" {
		m = http.MethodPost
		if body == "" {
			m = http.MethodGet
		}
	}
	client := &http.Client{Timeout: 10 * time.Second}
	var mu sync.Mutex
	codes := map[int]int{}
	jobs := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < *conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range jobs {
				var rdr io.Reader
				if body != "" {
					rdr = strings.NewReader(body)
				}
				req, err := http.NewRequest(m, strings.TrimRight(*proxy, "/")+p, rdr)
				if err != nil {
					log.Fatal(err)
				}
				req.Header.Set("X-Forwarded-For", *ip)
				req.Header.Set("Content-Type", "application/json")
				if *prof == "anthropic" {
					req.Header.Set("X-Api-Key", key)
					req.Header.Set("Anthropic-Version", "2023-06-01")
				} else {
					req.Header.Set("Authorization", "Bearer "+key)
				}
				code := 0
				if resp, err := client.Do(req); err == nil {
					_, _ = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					code = resp.StatusCode
				}
				mu.Lock()
				codes[code]++
				mu.Unlock()
			}
		}()
	}
	for i := 0; i < *n; i++ {
		jobs <- struct{}{}
	}
	close(jobs)
	wg.Wait()
	var parts []string
	for code, c := range codes {
		parts = append(parts, fmt.Sprintf("%d×%d", c, code))
	}
	fmt.Printf("  %-15s %-4s %-22s %s\n", *ip, m, p, strings.Join(parts, " "))
	return nil
}

// ---- history --------------------------------------------------------------

// usagePlan is how one key is used on a normal week.
type usagePlan struct {
	ips     []string // weighted by repetition
	ops     []string // weighted by repetition
	models  []string // weighted by repetition; empty for generic
	perHour float64  // requests per hour at the daily peak (CI runs a day when bursty)
	office  bool     // weekdays, working hours only
	bursty  bool     // CI: short bursts instead of a steady flow
	until   float64  // stop this many days before now (0: until now)
}

var plans = map[string]usagePlan{
	"laptop": {
		ips: []string{"203.0.113.10", "203.0.113.10", "203.0.113.11"}, ops: []string{"POST /v1/chat/completions"},
		models: []string{"gpt-4o-mini", "gpt-4o-mini", "gpt-4o"}, perHour: 14, office: true,
	},
	"ci-github": {
		ips: []string{"198.51.100.7"}, ops: []string{"POST /v1/messages"},
		models: []string{"claude-sonnet-4-5"}, perHour: 5, bursty: true,
	},
	"prod-api": {
		ips: []string{"192.0.2.20", "192.0.2.21"}, ops: []string{"POST /v1/chat/completions"},
		models: []string{"gpt-4o-mini", "gpt-4o-mini", "gpt-4o-mini", "gpt-4o"}, perHour: 90,
	},
	"support-bot": {
		ips: []string{"192.0.2.20"}, ops: []string{"POST /v1/messages"},
		models: []string{"claude-haiku-4-5"}, perHour: 36,
	},
	"billing-svc": {
		ips: []string{"192.0.2.30"}, ops: []string{"POST /v1/charges", "POST /v1/charges", "GET /v1/customers/*"},
		perHour: 16,
	},
	"staging-worker": {
		ips: []string{"192.0.2.40"}, ops: []string{"POST /v1/chat/completions"},
		models: []string{"gpt-4o-mini"}, perHour: 6, until: 0.05,
	},
	"old-intern": {
		ips: []string{"203.0.113.10"}, ops: []string{"POST /v1/chat/completions"},
		models: []string{"gpt-4o-mini", "gpt-4o"}, perHour: 5, office: true, until: 4.3,
	},
}

func history(args []string) error {
	fs := flag.NewFlagSet("history", flag.ContinueOnError)
	dbPath := fs.String("db", "", "keman.db (the server must be stopped)")
	geoDir := fs.String("geoip", "", "directory written by demo geoip")
	days := fs.Float64("days", 8, "days of history before now")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx := context.Background()
	st, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	geo, err := geoip.Open(filepath.Join(*geoDir, "country.mmdb"), filepath.Join(*geoDir, "asn.mmdb"))
	if err != nil {
		return err
	}
	defer geo.Close()
	prices, err := price.Load("")
	if err != nil {
		return err
	}
	keys, err := st.ListKeys(ctx)
	if err != nil {
		return err
	}
	creds, err := st.ListCredentials(ctx)
	if err != nil {
		return err
	}
	ups, err := st.ListUpstreams(ctx)
	if err != nil {
		return err
	}
	pols, err := st.ListPolicies(ctx)
	if err != nil {
		return err
	}
	// Spend counters exist only for keys with a cap; the UI shows other
	// keys' spend from their events.
	capped := map[string]bool{}
	for _, p := range pols {
		capped[p.KeyID] = p.DailyCapMicro != nil || p.MonthlyCapMicro != nil
	}
	profileOf := map[string]string{}
	for _, c := range creds {
		for _, u := range ups {
			if u.ID == c.UpstreamID {
				profileOf[c.ID] = u.Profile
			}
		}
	}

	now := time.Now().UTC()
	start := now.Add(-time.Duration(*days * 24 * float64(time.Hour)))
	rng := rand.New(rand.NewSource(42))
	clk := clock.NewFake(start)
	engine := detect.New(clk, detect.DefaultConfig())
	spend := map[[2]string]int64{}
	total := 0
	for _, k := range keys {
		plan, ok := plans[k.Name]
		if !ok {
			continue
		}
		prof := profileOf[k.CredentialID]
		end := now.Add(-time.Duration(plan.until * 24 * float64(time.Hour)))
		events := plan.events(rng, k, prof, start, end)
		var last model.Baseline
		for _, ev := range events {
			ev.Country, ev.ASN = geo.Lookup(net.ParseIP(ev.IP))
			if cost, ok := prices.Cost(ev.Model, ev.TokensIn, ev.TokensOut, 0, 0, false); ok && ev.Model != "" {
				ev.CostMicro = &cost
				if capped[k.ID] {
					spend[[2]string{k.ID, state.DayPeriod(ev.Time)}] += cost
					spend[[2]string{k.ID, state.MonthPeriod(ev.Time)}] += cost
				}
			}
			if err := st.InsertEvent(ctx, ev); err != nil {
				return err
			}
			clk.Set(ev.Time)
			last = engine.Observe(ev).Baseline
		}
		if len(events) > 0 {
			if err := st.SaveBaseline(ctx, last); err != nil {
				return err
			}
		}
		total += len(events)
		fmt.Printf("  %-15s %5d requests over %.0f days\n", k.Name, len(events), *days-plan.until)
	}
	var rows []model.SpendRow
	for k, v := range spend {
		rows = append(rows, model.SpendRow{KeyID: k[0], Period: k[1], Micro: v})
	}
	if err := st.SaveSpend(ctx, rows); err != nil {
		return err
	}
	if err := st.Close(); err != nil {
		return err
	}
	return backdate(*dbPath, start.Add(-90*time.Minute), now)
}

// events lays out one key's requests in 5-minute slots, following a daily
// curve that peaks mid-afternoon UTC.
func (p usagePlan) events(rng *rand.Rand, k model.VirtualKey, prof string, start, end time.Time) []model.Event {
	var out []model.Event
	slot := 5 * time.Minute
	burst := 0
	for t := start.Truncate(slot); t.Before(end); t = t.Add(slot) {
		h := float64(t.Hour()) + float64(t.Minute())/60
		curve := 0.15 + 0.85*math.Max(0, math.Sin(math.Pi*(h-5)/16))
		if p.office {
			wd := t.Weekday()
			if wd == time.Saturday || wd == time.Sunday || t.Hour() < 7 || t.Hour() > 18 {
				continue
			}
			curve = 1
		}
		n := 0
		if p.bursty {
			// perHour is the number of CI runs a day here.
			if burst == 0 && rng.Float64() < p.perHour/288 {
				burst = 3 + rng.Intn(3)
			}
			if burst > 0 {
				n = 8 + rng.Intn(10)
				burst--
			}
		} else {
			mean := p.perHour / 12 * curve
			n = int(mean)
			if rng.Float64() < mean-float64(n) {
				n++
			}
		}
		for i := 0; i < n; i++ {
			ts := t.Add(time.Duration(rng.Int63n(int64(slot))))
			if !ts.Before(end) {
				continue
			}
			ev := model.Event{
				Time: ts, KeyID: k.ID, Kind: k.Kind, IP: pick(rng, p.ips), Operation: pick(rng, p.ops),
				Status: 200, Profile: prof, Mode: model.ModeAlertOnly,
				ReqBytes: int64(400 + rng.Intn(3000)), RespBytes: int64(300 + rng.Intn(2500)),
			}
			if len(p.models) > 0 {
				ev.Model = pick(rng, p.models)
				ev.TokensIn = int64(600 + rng.Intn(2400))
				ev.TokensOut = int64(80 + rng.Intn(700))
				ev.LatencyMS = int64(400 + rng.Intn(2200))
			} else {
				ev.LatencyMS = int64(90 + rng.Intn(220))
			}
			if rng.Float64() < 0.004 {
				ev.Status = 429
			}
			out = append(out, ev)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Time.Before(out[j].Time) })
	return out
}

func pick(rng *rand.Rand, list []string) string { return list[rng.Intn(len(list))] }

// backdate moves setup (key creation, policies, credentials) to before the
// history starts, keeping the order the script ran it in. Key expiry moves
// too, so each key keeps the lifetime it was created with.
func backdate(dbPath string, at, now time.Time) error {
	db, err := sql.Open("sqlite", "file:"+dbPath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return err
	}
	defer db.Close()
	shift := now.Sub(at)
	for _, tc := range [][2]string{
		{"virtual_keys", "created_at"},
		{"virtual_keys", "expires_at"},
		{"credentials", "created_at"},
		{"upstreams", "created_at"},
		{"audit_log", "ts"},
	} {
		table, col := tc[0], tc[1]
		q := `SELECT id, ` + col + ` FROM ` + table + ` WHERE ` + col + ` IS NOT NULL`
		rows, err := db.Query(q)
		if err != nil {
			return err
		}
		type row struct{ id, ts string }
		var list []row
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.id, &r.ts); err != nil {
				rows.Close()
				return err
			}
			list = append(list, r)
		}
		rows.Close()
		for _, r := range list {
			t, err := time.Parse(time.RFC3339Nano, r.ts)
			if err != nil {
				continue
			}
			if _, err := db.Exec(`UPDATE `+table+` SET `+col+` = ? WHERE id = ?`, t.Add(-shift).UTC().Format(time.RFC3339Nano), r.id); err != nil {
				return err
			}
		}
	}
	return nil
}
