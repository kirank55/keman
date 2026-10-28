// Package price loads model prices in microdollars per million tokens.
package price

import (
	_ "embed"
	"encoding/json"
	"os"

	"github.com/kirank55/keman/internal/money"
)

//go:embed prices.json
var builtin []byte

// Model prices are microdollars per million tokens.
// A nil cached or cache-write price means those tokens bill as normal input.
type Model struct {
	Input      int64
	Output     int64
	Cached     *int64
	CacheWrite *int64
}

type Table struct {
	Version string
	models  map[string]Model
}

type file struct {
	Version string               `json:"version"`
	Models  map[string]jsonModel `json:"models"`
}

type jsonModel struct {
	Input      int64  `json:"input"`
	Output     int64  `json:"output"`
	Cached     *int64 `json:"cached_input"`
	CacheWrite *int64 `json:"cache_write"`
}

// Load reads the embedded snapshot, then merges an optional overlay file.
// Overlay entries replace the same model name.
func Load(overlayPath string) (*Table, error) {
	t, err := parse(builtin)
	if err != nil {
		return nil, err
	}
	if overlayPath == "" {
		return t, nil
	}
	b, err := os.ReadFile(overlayPath)
	if err != nil {
		return nil, err
	}
	over, err := parse(b)
	if err != nil {
		return nil, err
	}
	for k, v := range over.models {
		t.models[k] = v
	}
	if over.Version != "" {
		t.Version = over.Version
	}
	return t, nil
}

func parse(b []byte) (*Table, error) {
	var f file
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	t := &Table{Version: f.Version, models: make(map[string]Model, len(f.Models))}
	for name, m := range f.Models {
		t.models[name] = Model{Input: m.Input, Output: m.Output, Cached: m.Cached, CacheWrite: m.CacheWrite}
	}
	return t, nil
}

func (t *Table) Lookup(model string) (Model, bool) {
	if t == nil {
		return Model{}, false
	}
	m, ok := t.models[model]
	return m, ok
}

// Cost returns the microdollar cost of a completed call.
// inputIncludesCached is true for OpenAI, where Input already counts cached tokens.
func (t *Table) Cost(model string, input, output, cached, cacheWrite int64, inputIncludesCached bool) (int64, bool) {
	m, ok := t.Lookup(model)
	if !ok {
		return 0, false
	}
	if cached < 0 {
		cached = 0
	}
	if inputIncludesCached {
		if cached > input {
			cached = input
		}
		input -= cached
	}
	cachedPrice := m.Input
	if m.Cached != nil {
		cachedPrice = *m.Cached
	}
	writePrice := m.Input
	if m.CacheWrite != nil {
		writePrice = *m.CacheWrite
	}
	total := money.TokenCost(input, m.Input) +
		money.TokenCost(output, m.Output) +
		money.TokenCost(cached, cachedPrice) +
		money.TokenCost(cacheWrite, writePrice)
	return total, true
}

// Reserve estimates the hold for a request that has not run yet.
// maxTokens nil means the output term is defaultReservation.
func (t *Table) Reserve(model string, bodyBytes int64, maxTokens *int64, defaultReservation int64) (int64, bool) {
	m, ok := t.Lookup(model)
	if !ok {
		return 0, false
	}
	inTokens := bodyBytes / 4
	if inTokens < 0 {
		inTokens = 0
	}
	hold := money.TokenCostUp(inTokens, m.Input)
	if maxTokens == nil {
		if defaultReservation < 0 {
			defaultReservation = 0
		}
		return money.Add(hold, defaultReservation), true
	}
	return money.Add(hold, money.TokenCostUp(*maxTokens, m.Output)), true
}
