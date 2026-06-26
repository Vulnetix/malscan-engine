package iocscan

import (
	"reflect"
	"testing"
)

func testMatcher() *Matcher {
	set := NewIndicatorSet()
	set.Add(&Indicator{Type: TypeDomain, Value: "evil-malware.example", Name: "Malicious domain", Severity: "critical"})
	set.Add(&Indicator{Type: TypeIPv4, Value: "185.100.157.127"})
	set.Add(&Indicator{Type: TypeURL, Value: "http://evil-malware.example/payload"})
	return NewMatcher(set, 1)
}

func TestMatcherMatchText(t *testing.T) {
	m := testMatcher()
	content := "line one\nconst u = 'http://evil-malware.example/payload'\nline three\n"

	ev := m.MatchText("src/app.js", content)

	// URL hit on line 2, plus the bare-domain hit from the same URL.
	var url, dom *Evidence
	for i := range ev {
		switch ev[i].IndicatorType {
		case TypeURL:
			url = &ev[i]
		case TypeDomain:
			dom = &ev[i]
		}
	}
	if url == nil {
		t.Fatalf("no URL evidence; got %d evidence", len(ev))
	}
	if url.FilePath != "src/app.js" || url.RelPath != "src/app.js" {
		t.Errorf("name not recorded on evidence: %+v", url)
	}
	if url.LineNumber != 2 {
		t.Errorf("URL line = %d, want 2", url.LineNumber)
	}
	if url.IsBinary {
		t.Error("text match wrongly flagged IsBinary")
	}
	if !reflect.DeepEqual(url.ContextBefore, []string{"line one"}) {
		t.Errorf("ContextBefore = %q, want [line one]", url.ContextBefore)
	}
	if !reflect.DeepEqual(url.ContextAfter, []string{"line three"}) {
		t.Errorf("ContextAfter = %q, want [line three]", url.ContextAfter)
	}
	if dom == nil || dom.Indicator == nil || dom.Indicator.Severity != "critical" {
		t.Errorf("domain evidence/provenance missing: %+v", dom)
	}
}

func TestMatcherMatchTextNoHit(t *testing.T) {
	m := testMatcher()
	if ev := m.MatchText("README.md", "see github.com and example.org\n"); len(ev) != 0 {
		t.Fatalf("benign content produced %d evidence: %+v", len(ev), ev)
	}
}

func TestMatcherMatchBytesBinary(t *testing.T) {
	m := testMatcher()
	// ELF magic + NUL padding + an embedded known-bad domain.
	blob := append([]byte{0x7f, 'E', 'L', 'F'}, make([]byte, 8)...)
	blob = append(blob, []byte("cfg evil-malware.example end")...)
	blob = append(blob, 0x00)

	ev := m.MatchBytes("bin/agent", blob)
	var dom *Evidence
	for i := range ev {
		if ev[i].IndicatorType == TypeDomain {
			dom = &ev[i]
		}
	}
	if dom == nil {
		t.Fatalf("binary domain not matched; got %d evidence", len(ev))
	}
	if !dom.IsBinary {
		t.Error("binary match not flagged IsBinary")
	}
	if dom.ByteOffset <= 0 {
		t.Errorf("ByteOffset = %d, want > 0", dom.ByteOffset)
	}
}

func TestMatcherMatchBytesText(t *testing.T) {
	m := testMatcher()
	// No NUL / ELF magic → treated as text, line numbers preserved.
	ev := m.MatchBytes("a/b.env", []byte("X=1\nIP=185.100.157.127\n"))
	if len(ev) != 1 || ev[0].IndicatorType != TypeIPv4 || ev[0].LineNumber != 2 {
		t.Fatalf("expected one ipv4 hit on line 2, got %+v", ev)
	}
	if ev[0].IsBinary {
		t.Error("non-binary bytes wrongly flagged IsBinary")
	}
}

func TestScanWithPreloadedSet(t *testing.T) {
	// Options.Set bypasses the FeedLoader entirely (no network, no cache).
	set := NewIndicatorSet()
	set.Add(&Indicator{Type: TypeDomain, Value: "evil-malware.example"})

	root := t.TempDir()
	writeFile(t, root, "pkg/index.js", "fetch('https://evil-malware.example/x')\n")

	rep, err := Scan(Options{Root: root, Set: set})
	if err != nil {
		t.Fatalf("Scan with preloaded set: %v", err)
	}
	if rep.IndicatorCount != 1 {
		t.Errorf("IndicatorCount = %d, want 1", rep.IndicatorCount)
	}
	if findEvidence(rep, "pkg/index.js", TypeDomain, "evil-malware.example") == nil {
		t.Fatalf("preloaded-set scan found nothing: %s", evidenceSummary(rep))
	}
	if len(rep.Warnings) != 0 {
		t.Errorf("preloaded-set scan should not warn: %+v", rep.Warnings)
	}
}
