package tui

import (
	"encoding/json"
	"time"
)

type keyWire struct {
	ID            string      `json:"id"`
	Name          string      `json:"name"`
	CredentialID  string      `json:"credential_id"`
	Kind          string      `json:"kind"`
	Status        string      `json:"status"`
	ExpiresAt     *time.Time  `json:"expires_at"`
	DryRunArmed   bool        `json:"dry_run_armed"`
	DryRunBlocked int         `json:"dry_run_blocked"`
	Policy        *policyWire `json:"policy"`
	SpendToday    int64       `json:"spend_today_microusd"`
	SpendMonth    int64       `json:"spend_month_microusd"`
	SpendOpen     int64       `json:"spend_open_microusd"`
	CreatedAt     time.Time   `json:"created_at"`
	LastSeen      *time.Time  `json:"last_seen_at"`
	LastIP        string      `json:"last_ip"`
	LastClient    string      `json:"last_client_name"`
	LastCountry   string      `json:"last_country"`
	Detections7d  int         `json:"detections_7d"`
	Exposure      []struct {
		Code     string `json:"code"`
		Severity string `json:"severity"`
		Message  string `json:"message"`
		Fix      string `json:"fix"`
	} `json:"exposure"`
}

type policyWire struct {
	Mode      string   `json:"mode"`
	RPM       *int     `json:"rpm"`
	Daily     *int64   `json:"daily_cap_microusd"`
	Monthly   *int64   `json:"monthly_cap_microusd"`
	Paths     []string `json:"paths"`
	Models    []string `json:"models"`
	CIDRs     []string `json:"cidrs"`
	Countries []string `json:"countries"`
}

func (w keyWire) toKey() Key {
	k := Key{
		ID: w.ID, Name: w.Name, CredentialID: w.CredentialID, Kind: w.Kind, Status: w.Status,
		ExpiresAt: w.ExpiresAt, DryRunArmed: w.DryRunArmed, DryRunBlocked: w.DryRunBlocked,
		SpendToday: w.SpendToday, SpendMonth: w.SpendMonth, SpendOpen: w.SpendOpen,
		CreatedAt: w.CreatedAt, LastIP: w.LastIP, LastClient: w.LastClient, LastCountry: w.LastCountry, Detections7d: w.Detections7d,
	}
	if w.LastSeen != nil {
		k.LastSeen = *w.LastSeen
	}
	for _, x := range w.Exposure {
		k.Exposure = append(k.Exposure, Exposure{Code: x.Code, Severity: x.Severity, Message: x.Message, Fix: x.Fix})
	}
	if w.Policy != nil {
		p := Policy{
			Mode: w.Policy.Mode, RPM: w.Policy.RPM,
			DailyCapMicro: w.Policy.Daily, MonthlyCapMicro: w.Policy.Monthly,
			Paths:     append([]string(nil), w.Policy.Paths...),
			Models:    append([]string(nil), w.Policy.Models...),
			CIDRs:     append([]string(nil), w.Policy.CIDRs...),
			Countries: append([]string(nil), w.Policy.Countries...),
		}
		k.Policy = &p
	}
	return k
}

type usageWire struct {
	Requests   int        `json:"requests"`
	TokensIn   int64      `json:"tokens_in"`
	TokensOut  int64      `json:"tokens_out"`
	Cached     int64      `json:"cached_tokens"`
	CacheWrite int64      `json:"cache_write_tokens"`
	CostMicro  int64      `json:"cost_microusd"`
	Priced     int        `json:"priced"`
	Estimated  int        `json:"estimated"`
	LastSeen   *time.Time `json:"last_seen"`
	Clients    []struct {
		IP       string    `json:"ip"`
		Name     string    `json:"name"`
		Country  string    `json:"country"`
		ASN      int       `json:"asn"`
		Requests int       `json:"requests"`
		LastSeen time.Time `json:"last_seen"`
	} `json:"clients"`
	Models []struct {
		Model     string `json:"model"`
		Requests  int    `json:"requests"`
		TokensIn  int64  `json:"tokens_in"`
		TokensOut int64  `json:"tokens_out"`
		CostMicro int64  `json:"cost_microusd"`
		Priced    int    `json:"priced"`
	} `json:"models"`
	Recent []struct {
		Time          time.Time `json:"time"`
		IP            string    `json:"ip"`
		Country       string    `json:"country"`
		ASN           int       `json:"asn"`
		Operation     string    `json:"operation"`
		Status        int       `json:"status"`
		LatencyMS     int64     `json:"latency_ms"`
		Model         string    `json:"model"`
		TokensIn      int64     `json:"tokens_in"`
		TokensOut     int64     `json:"tokens_out"`
		CostMicro     *int64    `json:"cost_microusd"`
		CostEstimated bool      `json:"cost_estimated"`
		BlockedCode   string    `json:"blocked_code"`
		ClientName    string    `json:"client_name"`
	} `json:"recent"`
}

func (w usageWire) toUsage() KeyUsage {
	u := KeyUsage{
		Requests: w.Requests, TokensIn: w.TokensIn, TokensOut: w.TokensOut,
		Cached: w.Cached, CacheWrite: w.CacheWrite, CostMicro: w.CostMicro,
		Priced: w.Priced, Estimated: w.Estimated,
		Clients: []UsageClient{}, Models: []UsageModel{}, Recent: []UsageRequest{},
	}
	if w.LastSeen != nil {
		u.LastSeen = *w.LastSeen
	}
	for _, c := range w.Clients {
		u.Clients = append(u.Clients, UsageClient{
			IP: c.IP, Name: c.Name, Country: c.Country, ASN: c.ASN, Requests: c.Requests, LastSeen: c.LastSeen,
		})
	}
	for _, m := range w.Models {
		u.Models = append(u.Models, UsageModel{
			Model: m.Model, Requests: m.Requests, TokensIn: m.TokensIn, TokensOut: m.TokensOut,
			CostMicro: m.CostMicro, Priced: m.Priced,
		})
	}
	for _, r := range w.Recent {
		u.Recent = append(u.Recent, UsageRequest{
			Time: r.Time, IP: r.IP, Country: r.Country, ASN: r.ASN, Operation: r.Operation,
			Status: r.Status, LatencyMS: r.LatencyMS, Model: r.Model, TokensIn: r.TokensIn,
			TokensOut: r.TokensOut, CostMicro: r.CostMicro, CostEstimated: r.CostEstimated,
			BlockedCode: r.BlockedCode, ClientName: r.ClientName,
		})
	}
	return u
}

func parseTime(s string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, s)
}

func parseConfirm(body []byte) (*ConfirmError, error) {
	var wire struct {
		DryRun DryRun `json:"dry_run"`
		Error  struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		return nil, err
	}
	return &ConfirmError{Message: wire.Error.Message, Report: wire.DryRun}, nil
}
