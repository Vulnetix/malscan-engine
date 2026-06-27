package iocscan

import (
	"strings"
	"testing"
)

// hasIPv4 reports whether ev contains an IPv4 hit for value.
func hasIPv4(ev []Evidence, value string) bool {
	for _, e := range ev {
		if e.IndicatorType == TypeIPv4 && e.IndicatorValue == value {
			return true
		}
	}
	return false
}

const knownBadIP = "185.100.157.127" // seeded by testMatcher()

// TestIPv4BoundaryRejectsNumberRuns: a known-bad IP embedded in a longer dotted
// or signed number run (version, coordinate, range) is NOT a usage of an
// address and must not match.
func TestIPv4BoundaryRejectsNumberRuns(t *testing.T) {
	m := testMatcher()
	reject := []string{
		"transform: translate(-" + knownBadIP + ", 4)", // signed coordinate
		"version " + knownBadIP + ".8 released",          // 5-octet dotted run
		"range " + knownBadIP + "-200 allowed",           // numeric range
		"v" + knownBadIP,                                 // leading digit/letter glue handled by \b too
	}
	for _, line := range reject {
		if lm := m.matchLine(line, false); ipv4InMatches(lm) {
			t.Errorf("line %q wrongly matched an IPv4", line)
		}
	}
}

// TestIPv4StillMatchesRealUsage: a real address delimited by IP-plausible
// characters still matches — recall is preserved.
func TestIPv4StillMatchesRealUsage(t *testing.T) {
	m := testMatcher()
	accept := []string{
		"connect to " + knownBadIP + " now",   // whitespace
		`host = "` + knownBadIP + `"`,          // quoted
		"http://" + knownBadIP + "/payload",    // URL host
		"tcp://" + knownBadIP + ":4444",        // scheme + port
		"(" + knownBadIP + ")",                 // parens
	}
	for _, line := range accept {
		if lm := m.matchLine(line, false); !ipv4InMatches(lm) {
			t.Errorf("line %q should have matched the known-bad IPv4", line)
		}
	}
}

// TestIPv4SuppressedInGeneratedFiles: vector/source-map/minified files are
// numeric-noise sources — bare IPv4 matching is suppressed there.
func TestIPv4SuppressedInGeneratedFiles(t *testing.T) {
	m := testMatcher()
	content := "data " + knownBadIP + " more\n"
	for _, name := range []string{"assets/logo.svg", "dist/app.js.map", "dist/vendor.min.js"} {
		if ev := m.MatchText(name, content); hasIPv4(ev, knownBadIP) {
			t.Errorf("%s: IPv4 should be suppressed in a generated/minified file", name)
		}
	}
	// The same content in ordinary source DOES match.
	if ev := m.MatchText("src/agent.go", content); !hasIPv4(ev, knownBadIP) {
		t.Error("ordinary source: known-bad IPv4 should match")
	}
}

// TestIPv4SuppressedOnMinifiedLine: a pathologically long, whitespace-free line
// (minified bundle) suppresses IPv4 even when the filename is unremarkable.
func TestIPv4SuppressedOnMinifiedLine(t *testing.T) {
	m := testMatcher()
	minified := strings.Repeat("a", 2500) + knownBadIP + strings.Repeat("b", 50)
	if ev := m.MatchText("bundle.js", minified+"\n"); hasIPv4(ev, knownBadIP) {
		t.Error("IPv4 on a minified line should be suppressed")
	}
	// A short line with the same IP still matches.
	if ev := m.MatchText("bundle.js", "x = "+knownBadIP+"\n"); !hasIPv4(ev, knownBadIP) {
		t.Error("IPv4 on a normal line should match")
	}
}

func TestStrictIPv4(t *testing.T) {
	good := []string{"1.2.3.4", "185.100.157.127", "0.0.0.0", "255.255.255.255"}
	bad := []string{
		"1.2.3", "1.2.3.4.5", "256.1.1.1", "1.2.3.256",
		"01.2.3.4", "1.02.3.4", "1.2.3.4.", ".1.2.3.4", "1.2.3.4444", "1..2.3",
	}
	for _, s := range good {
		if !strictIPv4(s) {
			t.Errorf("strictIPv4(%q) = false, want true", s)
		}
	}
	for _, s := range bad {
		if strictIPv4(s) {
			t.Errorf("strictIPv4(%q) = true, want false", s)
		}
	}
}

func ipv4InMatches(lm []lineMatch) bool {
	for _, m := range lm {
		if m.typ == TypeIPv4 {
			return true
		}
	}
	return false
}
