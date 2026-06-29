package detect

import "testing"

// These regressions pin the non-IOC false positives surfaced by the website
// repo's malscan SARIF: B-TYPOSQUAT mislabelling legitimate npm packages via the
// AUR brand corpus, and the chmod/download dual-use shell rules minting critical
// on a package's manually-run npm scripts. The fix keeps real detection — a 1-edit
// AUR typo, a chmod-exec in an install hook or an auto-exec PKGBUILD still mint —
// while the benign-context occurrences are gated out or demoted to context.

func TestTyposquatEcosystemGate(t *testing.T) {
	cases := []struct {
		name     string
		ctx      *PackageContext
		evidence bool // B-TYPOSQUAT present as ClassEvidence
		context  bool // B-TYPOSQUAT present as ClassContext (and NOT evidence)
		absent   bool // B-TYPOSQUAT must be entirely absent
	}{
		{
			name:   "d3-zoom on npm is not a typosquat",
			ctx:    &PackageContext{Name: "d3-zoom", Ecosystem: "npm"},
			absent: true,
		},
		{
			name:   "@types/d3-zoom on npm is not a typosquat",
			ctx:    &PackageContext{Name: "@types/d3-zoom", Ecosystem: "npm"},
			absent: true,
		},
		{
			name:    "d3-zoom on aur embeds 'zoom' but only as context",
			ctx:     &PackageContext{Name: "d3-zoom", Ecosystem: "aur"},
			context: true,
		},
		{
			name:     "1-edit typo of a top aur package is evidence",
			ctx:      &PackageContext{Name: "paruu", Ecosystem: "aur"},
			evidence: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := Detect(tc.ctx)
			switch {
			case tc.absent:
				if has(f, "B-TYPOSQUAT") {
					t.Errorf("B-TYPOSQUAT must be absent for %q; findings=%v", tc.ctx.Name, ids(f))
				}
			case tc.evidence:
				if !inClass(f, "B-TYPOSQUAT", ClassEvidence) {
					t.Errorf("expected B-TYPOSQUAT as ClassEvidence; findings=%v", ids(f))
				}
			case tc.context:
				if !inClass(f, "B-TYPOSQUAT", ClassContext) {
					t.Errorf("expected B-TYPOSQUAT as ClassContext; findings=%v", ids(f))
				}
				if inClass(f, "B-TYPOSQUAT", ClassEvidence) {
					t.Errorf("embedding B-TYPOSQUAT must NOT be ClassEvidence; findings=%v", ids(f))
				}
			}
		})
	}
}

func TestChmodExecChainHookContext(t *testing.T) {
	// dagre-d3-es ships exactly this manual bundle script in its package.json.
	const manifest = `{"scripts":{"bundle":"chmod +x bundle.sh ; ./bundle.sh && cp dist/x .."}}`
	cases := []struct {
		name       string
		ctx        *PackageContext
		malicious  bool
		evidenceID string // present as ClassEvidence
		contextID  string // present as ClassContext, NOT ClassEvidence
	}{
		{
			name:      "chmod-exec in a manual npm bundle script is context only",
			ctx:       &PackageContext{Name: "dagre-d3-es", Ecosystem: "npm", PkgbuildContent: manifest, PkgbuildExecutes: false},
			malicious: false,
			contextID: "P-CHMOD-EXEC-CHAIN",
		},
		{
			name:       "chmod-exec in an npm install hook still mints",
			ctx:        &PackageContext{Name: "p", Ecosystem: "npm", InstallScriptContent: `"postinstall": "chmod +x x.sh ; ./x.sh"`},
			malicious:  true,
			evidenceID: "P-INSTALL-CHMOD-EXEC",
		},
		{
			name:       "chmod-exec in an auto-exec PKGBUILD is evidence",
			ctx:        &PackageContext{Name: "p", Ecosystem: "aur", PkgbuildContent: "build() {\n  chmod +x x.sh ; ./x.sh\n}", PkgbuildExecutes: true},
			malicious:  true,
			evidenceID: "P-CHMOD-EXEC-CHAIN",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := Detect(tc.ctx)
			if got := IsMalicious(f); got != tc.malicious {
				t.Fatalf("IsMalicious=%v want %v; findings=%v", got, tc.malicious, ids(f))
			}
			if tc.evidenceID != "" && !inClass(f, tc.evidenceID, ClassEvidence) {
				t.Errorf("expected %q as ClassEvidence; findings=%v", tc.evidenceID, ids(f))
			}
			if tc.contextID != "" {
				if !inClass(f, tc.contextID, ClassContext) {
					t.Errorf("expected %q as ClassContext; findings=%v", tc.contextID, ids(f))
				}
				if inClass(f, tc.contextID, ClassEvidence) {
					t.Errorf("%q must NOT be ClassEvidence in a manually-run manifest; findings=%v", tc.contextID, ids(f))
				}
			}
		})
	}
}
