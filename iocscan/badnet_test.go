package iocscan

import (
	"testing"

	"github.com/vulnetix/malscan-engine/badnet"
)

func TestAddBadnetSet(t *testing.T) {
	bn := badnet.NewEmpty()
	bn.AddIP("45.137.21.9")
	bn.AddIP("2606:4700::1111")
	bn.AddDomain("malware-drop.xyz")
	bn.AddDomain("github.com") // benign — dropped by badnet itself
	bn.AddIP("203.0.113.5")    // benign TEST-NET — dropped

	set := NewIndicatorSet()
	set.AddBadnetSet(bn)

	if set.LookupIP("45.137.21.9") == nil {
		t.Error("expected badnet IPv4 in the indicator set")
	}
	if set.LookupIP("2606:4700:0000:0000:0000:0000:0000:1111") == nil {
		t.Error("expected badnet IPv6 in the indicator set")
	}
	if set.LookupDomain("malware-drop.xyz") == nil {
		t.Error("expected badnet domain in the indicator set")
	}
	if set.LookupDomain("github.com") != nil {
		t.Error("benign domain must not enter the set")
	}
	if set.LookupIP("203.0.113.5") != nil {
		t.Error("benign IP must not enter the set")
	}

	// A matcher over the merged set flags a referencing line.
	m := NewMatcher(set, 0)
	if ev := m.MatchText("cfg.txt", "connect 45.137.21.9 then GET malware-drop.xyz\n"); len(ev) < 2 {
		t.Errorf("expected the merged badnet indicators to match, got %d evidence", len(ev))
	}
}
