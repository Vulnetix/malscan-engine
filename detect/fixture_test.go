package detect

import "testing"

// ctxFixture builds the minimal PackageContext detection tests share: the pkg
// name and ecosystem the detectors expect, with the primary build content set.
// See hookFixture for install-hook content.
func ctxFixture(eco, content string) *PackageContext {
	return &PackageContext{Name: "pkg", Ecosystem: eco, PkgbuildContent: content}
}

// hookFixture is ctxFixture for install-hook content.
func hookFixture(eco, hook string) *PackageContext {
	return &PackageContext{Name: "pkg", Ecosystem: eco, InstallScriptContent: hook}
}

// stubNowUnix pins the nowUnix package var so age-based detectors run against a
// fixed clock, and restores it when the test finishes.
func stubNowUnix(t *testing.T, ts int64) {
	t.Helper()
	old := nowUnix
	nowUnix = func() int64 { return ts }
	t.Cleanup(func() { nowUnix = old })
}
