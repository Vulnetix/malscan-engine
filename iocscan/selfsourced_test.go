package iocscan

import (
	"strings"
	"testing"

	"github.com/vulnetix/malscan-engine/detect"
)

// The STIX feed is generated from our own malware advisory records, so an
// indicator can exist purely because a previous mint referenced it. Left
// unchecked that is a self-reinforcing loop: package references host -> mint ->
// host harvested into feed -> every package referencing it minted -> more mints,
// each one raising the "observed in N advisory records" count that reads as
// corroboration. These tests pin the provenance-based demotion that breaks it.
//
// The real-world case: api.anthropic.com, published as "Malicious domain observed
// in 1353 Vulnetix malware advisory record(s)" with source:registry provenance,
// had minted 177 crates.io packages as malware on a bare host match alone.

func selfSourcedIndicator(t IndicatorType, value string) *Indicator {
	return &Indicator{
		Type:   t,
		Value:  value,
		Name:   "Malicious " + string(t) + " " + value,
		Labels: []string{"malicious-activity", "source:registry", "ecosystem:generic"},
	}
}

func externalIndicator(t IndicatorType, value string) *Indicator {
	return &Indicator{
		Type:   t,
		Value:  value,
		Name:   "Malicious " + string(t) + " " + value,
		Labels: []string{"malicious-activity", "ecosystem:generic"},
	}
}

func TestIndicatorClassFloorDemotesSelfSourcedBareHost(t *testing.T) {
	cases := []struct {
		name string
		ind  *Indicator
		want detect.Class
	}{
		{
			name: "self-sourced domain is corroboration only",
			ind:  selfSourcedIndicator(TypeDomain, "api.anthropic.com"),
			want: detect.ClassContext,
		},
		{
			name: "self-sourced ipv4 is corroboration only",
			ind:  selfSourcedIndicator(TypeIPv4, "223.5.5.5"),
			want: detect.ClassContext,
		},
		{
			name: "self-sourced ipv6 is corroboration only",
			ind:  selfSourcedIndicator(TypeIPv6, "2001:db8::1"),
			want: detect.ClassContext,
		},
		{
			// A specific path is a real artefact even when we asserted it
			// ourselves — it is not an incidental reference to a service.
			name: "self-sourced url keeps full weight",
			ind:  selfSourcedIndicator(TypeURL, "https://api.anthropic.com/v1/steal"),
			want: "",
		},
		{
			// Independent corroboration: a genuine C2 domain must still mint.
			name: "externally-sourced domain keeps full weight",
			ind:  externalIndicator(TypeDomain, "evilc2.example"),
			want: "",
		},
		{
			name: "externally-sourced ipv4 keeps full weight",
			ind:  externalIndicator(TypeIPv4, "185.100.157.127"),
			want: "",
		},
		{
			name: "nil indicator is not demoted",
			ind:  nil,
			want: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := indicatorClassFloor(tc.ind); got != tc.want {
				t.Errorf("indicatorClassFloor() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestWorstClassNeverPromotes guards the composition: a file already demoted by
// tiering must not be promoted back to evidence by an indicator with no floor.
func TestWorstClassNeverPromotes(t *testing.T) {
	cases := []struct {
		a, b, want detect.Class
	}{
		{detect.ClassContext, "", detect.ClassContext},
		{"", detect.ClassContext, detect.ClassContext},
		{detect.ClassContext, detect.ClassContext, detect.ClassContext},
		{"", "", ""},
	}
	for _, tc := range cases {
		if got := worstClass(tc.a, tc.b); got != tc.want {
			t.Errorf("worstClass(%q, %q) = %q, want %q", tc.a, tc.b, got, tc.want)
		}
	}
}

// TestMatchTextSelfSourcedHostIsNotMalicious is the end-to-end assertion that
// matters: a legitimate package referencing a self-sourced host produces evidence
// (so it is still visible and can raise a score) but does NOT report Malicious,
// which is what gates the mint.
func TestMatchTextSelfSourcedHostIsNotMalicious(t *testing.T) {
	// NOT api.anthropic.com: that host is now allowlisted outright, which is the
	// other half of this fix, so it never reaches the matcher. This test is about
	// the provenance rule holding for ANY self-sourced host, including ones no
	// allowlist will ever enumerate.
	set := NewIndicatorSet()
	set.Add(selfSourcedIndicator(TypeDomain, "api.someprovider.io"))
	m := NewMatcher(set, DefaultContextLines)

	src := `            Provider::Some => "https://api.someprovider.io",`
	ev := m.MatchText("src/provider.rs", src)
	if len(ev) == 0 {
		t.Fatal("expected the reference to still be recorded as evidence")
	}
	for _, e := range ev {
		if e.Class != detect.ClassContext {
			t.Errorf("hit on %s has Class %q, want context — a self-sourced bare host must not carry a verdict alone",
				e.IndicatorValue, e.Class)
		}
	}
	if (&Report{Evidence: ev}).Malicious() {
		t.Error("Report.Malicious() = true for a self-sourced bare-host reference; this is the api.anthropic.com false-positive class")
	}
}

// TestMatchTextExternalHostStillMalicious is the other half: the change must not
// blind the scanner to a genuine, independently-sourced C2 host.
func TestMatchTextExternalHostStillMalicious(t *testing.T) {
	// NOT a .example host — that is an example TLD and is allowlisted at set
	// construction, so it would never match regardless of provenance.
	set := NewIndicatorSet()
	set.Add(externalIndicator(TypeDomain, "evilc2beacon.io"))
	m := NewMatcher(set, DefaultContextLines)

	ev := m.MatchText("build.rs", `let c2 = "https://evilc2beacon.io/beacon";`)
	if len(ev) == 0 {
		t.Fatal("expected a hit on the external C2 domain")
	}
	if !(&Report{Evidence: ev}).Malicious() {
		t.Error("Report.Malicious() = false for an externally-sourced C2 domain; the demotion is too broad")
	}
	if strings.Contains(strings.ToLower(string(ev[0].Class)), "context") {
		t.Errorf("external C2 hit was demoted to %q", ev[0].Class)
	}
}
