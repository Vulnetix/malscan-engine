package badhash

import "testing"

func TestSetAddHasNormalize(t *testing.T) {
	s := New()
	sha256 := "44d88612fea8a8f36de82e1278abb02f5a1c2d4d1b9e0c8f6b3a2e1d0c9b8a77"
	s.Add(sha256)

	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"exact", sha256, true},
		{"uppercase", "44D88612FEA8A8F36DE82E1278ABB02F5A1C2D4D1B9E0C8F6B3A2E1D0C9B8A77", true},
		{"sha256-prefix", "sha256:" + sha256, true},
		{"quoted", "'" + sha256 + "'", true},
		{"unknown", "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef0", false},
		{"skip-token", "SKIP", false},
		{"too-short", "abc123", false},
		{"non-hex", "zzzz8612fea8a8f36de82e1278abb02f5a1c2d4d1b9e0c8f6b3a2e1d0c9b8a77", false},
	}
	for _, c := range cases {
		if got := s.Has(c.in); got != c.want {
			t.Errorf("%s: Has(%q) = %v, want %v", c.name, c.in, got, c.want)
		}
	}
}

func TestAddAllAndLen(t *testing.T) {
	s := New()
	base := s.Len() // embedded seed (currently 0)
	s.AddAll([]string{
		"44d88612fea8a8f36de82e1278abb02f5a1c2d4d1b9e0c8f6b3a2e1d0c9b8a77",
		"SKIP",                             // ignored
		"short",                            // ignored
		"d41d8cd98f00b204e9800998ecf8427e", // md5 length accepted
	})
	if got := s.Len() - base; got != 2 {
		t.Fatalf("AddAll added %d hashes, want 2", got)
	}
	if !s.Has("d41d8cd98f00b204e9800998ecf8427e") {
		t.Error("md5-length hash should be present")
	}
}
