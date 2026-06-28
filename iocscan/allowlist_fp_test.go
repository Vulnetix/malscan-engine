package iocscan

import "testing"

// TestIndicatorSetDropsBenign pins the match-time allowlist: benign domain / IP
// indicators that leaked into the feed never enter the match set (so they can't
// produce IOC-STIX-MATCH false positives), while real indicators — and ALL url
// indicators (a feed url is a specific known-bad URL) — are kept.
func TestIndicatorSetDropsBenign(t *testing.T) {
	set := NewIndicatorSet()
	set.AddAll([]*Indicator{
		{Type: TypeDomain, Value: "html.spec.whatwg.org"},
		{Type: TypeDomain, Value: "tidelift.com"},
		{Type: TypeDomain, Value: "github.com"},
		{Type: TypeIPv4, Value: "1.2.3.4"},
		{Type: TypeIPv4, Value: "192.0.2.10"},
		{Type: TypeDomain, Value: "evil-c2.io"},        // real → kept
		{Type: TypeIPv4, Value: "185.100.157.127"},     // real → kept
		{Type: TypeURL, Value: "https://github.com/x"}, // url indicators always kept
	})

	if set.LookupDomain("html.spec.whatwg.org") != nil ||
		set.LookupDomain("tidelift.com") != nil ||
		set.LookupDomain("github.com") != nil {
		t.Error("benign domains must be dropped from the indicator set")
	}
	if set.LookupIP("1.2.3.4") != nil || set.LookupIP("192.0.2.10") != nil {
		t.Error("reserved/placeholder IPs must be dropped from the indicator set")
	}
	if set.LookupDomain("evil-c2.io") == nil {
		t.Error("real malicious domain must be kept")
	}
	if set.LookupIP("185.100.157.127") == nil {
		t.Error("real malicious IP must be kept")
	}
	if set.LookupURL("https://github.com/x") == nil {
		t.Error("url indicators must always be kept (specific known-bad URLs)")
	}
}

// TestMatchTextNoBenignFP proves a file referencing only benign indicators
// produces no evidence even when those values were present in the feed.
func TestMatchTextNoBenignFP(t *testing.T) {
	set := NewIndicatorSet()
	set.AddAll([]*Indicator{
		{Type: TypeDomain, Value: "html.spec.whatwg.org"},
		{Type: TypeDomain, Value: "tidelift.com"},
	})
	m := NewMatcher(set, 0)
	content := "// see https://html.spec.whatwg.org/multipage and tidelift.com funding\n"
	if ev := m.MatchText("README.md", content); len(ev) != 0 {
		t.Errorf("benign references must yield no evidence; got %d", len(ev))
	}
}
