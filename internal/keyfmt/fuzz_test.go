package keyfmt

import "testing"

func FuzzParse(f *testing.F) {
	f.Add("kmn_abcdefgh_abcdefghijklmnopqrstuvwxyz012345") // keman:allow
	f.Add("kmn_")
	f.Add("")
	f.Add("kma_abcdefghijklmnopqrstuvwxyz0123456789ABCDE")
	f.Fuzz(func(t *testing.T, s string) {
		id, secret, err := Parse(s)
		if err != nil {
			return
		}
		if len(id) != 8 || len(secret) < 16 {
			t.Fatalf("parsed %q into id %q secret len %d", s, id, len(secret))
		}
		again, sec2, err := Parse(Prefix + id + "_" + secret)
		if err != nil || again != id || sec2 != secret {
			t.Fatalf("reparse %v %s %s", err, again, sec2)
		}
		sum := Hash(secret)
		if !MatchHash(secret, sum, sum) {
			t.Fatal("hash did not match")
		}
	})
}
