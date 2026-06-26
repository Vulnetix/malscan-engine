package iocscan

import "testing"

func TestParseBundleExtractsIndicators(t *testing.T) {
	bundle := makeBundle(
		tind{
			pattern: "[domain-name:value = 'baoreqygjveumkkxydcd.supabase.co']",
			name:    "Malicious domain baoreqygjveumkkxydcd.supabase.co",
			desc:    "Malicious domain observed in 1 advisory.",
			labels:  []string{"malicious-activity", "source:osm", "severity:critical", "ecosystem:rubygems"},
			extID:   "OSM-2026-342",
		},
		tind{
			pattern: "[ipv4-addr:value = '185.100.157.127']",
			name:    "Malicious IP",
			labels:  []string{"severity:high", "ecosystem:go"},
			extID:   "OSM-2026-343",
		},
		tind{
			pattern: "[url:value = 'http://evil.example/p']",
			name:    "Malicious URL",
			labels:  []string{"severity:medium"},
			extID:   "OSM-2026-344",
		},
	)

	inds, err := parseBundle([]byte(bundle))
	if err != nil {
		t.Fatalf("parseBundle: %v", err)
	}
	if len(inds) != 3 {
		t.Fatalf("got %d indicators, want 3 (marking-definition/identity must be skipped)", len(inds))
	}

	byVal := map[string]*Indicator{}
	for _, i := range inds {
		byVal[i.Value] = i
	}

	dom := byVal["baoreqygjveumkkxydcd.supabase.co"]
	if dom == nil || dom.Type != TypeDomain {
		t.Fatalf("domain indicator missing/mistyped: %+v", dom)
	}
	if dom.Severity != "critical" {
		t.Errorf("severity = %q, want critical", dom.Severity)
	}
	if dom.Ecosystem != "rubygems" {
		t.Errorf("ecosystem = %q, want rubygems", dom.Ecosystem)
	}
	if dom.Name == "" || dom.Description == "" {
		t.Errorf("name/description not retained: %+v", dom)
	}
	if len(dom.ExternalRefs) != 1 || dom.ExternalRefs[0].ExternalID != "OSM-2026-342" {
		t.Errorf("external refs not retained: %+v", dom.ExternalRefs)
	}

	if ip := byVal["185.100.157.127"]; ip == nil || ip.Type != TypeIPv4 {
		t.Errorf("ipv4 indicator missing/mistyped: %+v", ip)
	}
	if u := byVal["http://evil.example/p"]; u == nil || u.Type != TypeURL {
		t.Errorf("url indicator missing/mistyped: %+v", u)
	}
}

func TestParseBundleSkipsMalformedPatterns(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		wantOK  bool
	}{
		{"domain", "[domain-name:value = 'evil.example']", true},
		{"ipv4", "[ipv4-addr:value = '1.2.3.4']", true},
		{"ipv6", "[ipv6-addr:value = '2001:db8::1']", true},
		{"url", "[url:value = 'http://x.example/y']", true},
		{"spaces", "[domain-name:value='spaced.example']", true},
		{"unsupported-type", "[file:hashes.MD5 = 'abc']", false},
		{"empty-value", "[domain-name:value = '']", false},
		{"garbage", "not a pattern", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ind := indicatorFromPattern(c.pattern)
			if (ind != nil) != c.wantOK {
				t.Fatalf("indicatorFromPattern(%q) ok=%v want %v", c.pattern, ind != nil, c.wantOK)
			}
		})
	}
}

func TestIndicatorSetLookups(t *testing.T) {
	set := NewIndicatorSet()
	set.Add(&Indicator{Type: TypeDomain, Value: "Evil-Malware.Example"})
	set.Add(&Indicator{Type: TypeIPv4, Value: "185.100.157.127"})
	set.Add(&Indicator{Type: TypeIPv6, Value: "2001:db8::1"})
	set.Add(&Indicator{Type: TypeURL, Value: "http://evil.example/p"})

	if set.Len() != 4 {
		t.Fatalf("Len = %d, want 4", set.Len())
	}
	// Domain match is case-insensitive.
	if set.LookupDomain("evil-malware.example") == nil {
		t.Error("domain lookup should be case-insensitive")
	}
	// IP match is format-insensitive (zero-padding / compression).
	if set.LookupIP("2001:0db8:0000:0000:0000:0000:0000:0001") == nil {
		t.Error("ipv6 lookup should be canonicalised")
	}
	if set.LookupIP("185.100.157.127") == nil {
		t.Error("ipv4 lookup failed")
	}
	if set.LookupURL("http://evil.example/p") == nil {
		t.Error("url lookup failed")
	}
	// Negatives.
	if set.LookupDomain("good.example") != nil {
		t.Error("unexpected domain hit")
	}
}
