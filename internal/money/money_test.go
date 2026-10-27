package money

import "testing"

func TestParseUSD(t *testing.T) {
	got, err := ParseUSD("1.50")
	if err != nil || got != 1_500_000 {
		t.Fatalf("%d %v", got, err)
	}
	if _, err := ParseUSD("1.1234567"); err == nil {
		t.Fatal("expected too many decimals")
	}
	if FormatUSD(1_500_000) != "1.5" {
		t.Fatal(FormatUSD(1_500_000))
	}
}

func TestTokenCostHalfUpAndUp(t *testing.T) {
	if got := TokenCost(1, 1); got != 0 {
		t.Fatalf("half-up %d", got)
	}
	if got := TokenCostUp(1, 1); got != 1 {
		t.Fatalf("up %d", got)
	}
	if got := TokenCost(1_000_000, 2_500_000); got != 2_500_000 {
		t.Fatalf("got %d", got)
	}
}
