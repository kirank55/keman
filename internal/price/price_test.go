package price

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPresetPricesWinOverGlobal(t *testing.T) {
	tb, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := tb.Lookup("", "openai/gpt-oss-120b"); ok {
		t.Fatal("open models are priced per platform, not globally")
	}
	groq, ok := tb.Lookup("groq", "openai/gpt-oss-120b")
	if !ok {
		t.Fatal("groq price missing")
	}
	together, _ := tb.Lookup("together", "openai/gpt-oss-120b")
	cerebras, ok := tb.Lookup("cerebras", "gpt-oss-120b")
	if !ok || cerebras.Input == groq.Input || together.Cached != nil {
		t.Fatalf("groq %+v together %+v cerebras %+v", groq, together, cerebras)
	}
	if _, ok := tb.Lookup("groq", "gpt-4o-mini"); !ok {
		t.Fatal("a preset falls back to the global table")
	}
}

func TestOverlayMergesPresets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "prices.json")
	overlay := `{"presets":{"groq":{"openai/gpt-oss-120b":{"input":1,"output":2}},"local":{"m":{"input":3,"output":4}}}}`
	if err := os.WriteFile(path, []byte(overlay), 0o600); err != nil {
		t.Fatal(err)
	}
	tb, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := tb.Lookup("groq", "openai/gpt-oss-120b"); m.Input != 1 || m.Output != 2 {
		t.Fatalf("override %+v", m)
	}
	if _, ok := tb.Lookup("groq", "openai/gpt-oss-20b"); !ok {
		t.Fatal("overlay dropped built-in preset prices")
	}
	if m, ok := tb.Lookup("local", "m"); !ok || m.Output != 4 {
		t.Fatalf("new preset section %+v", m)
	}
}
