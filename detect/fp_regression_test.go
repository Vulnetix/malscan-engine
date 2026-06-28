package detect

import "testing"

// These tests pin the false-positive fixes that were driven by a malscan of a
// legitimate npm project (the website .vulnetix/malscan.sarif): the Arch-PKGBUILD
// analyzers (checksum arrays, source-URL hygiene) and the dual-use inline
// interpreters must not fire on a declarative manifest like package.json.

const samplePackageJSON = `{
  "name": "my-app",
  "version": "1.0.0",
  "homepage": "http://example.org/docs",
  "repository": "http://github.com/x/y",
  "scripts": {
    "build": "node -e \"require('./gen')\"",
    "test": "jest"
  },
  "dependencies": { "left-pad": "^1.0.0" }
}`

// A real Arch PKGBUILD with NO checksum array — P-NO-CHECKSUMS SHOULD fire here.
const samplePkgbuildNoSums = `pkgname=foo
pkgver=1.0.0
pkgrel=1
arch=('x86_64')
source=("http://downloads.example.org/foo-$pkgver.tar.gz")
build() {
  cd "$srcdir/foo-$pkgver"
  make
}`

func TestNoChecksumsSuppressedOnPackageJSON(t *testing.T) {
	f := Detect(&PackageContext{Name: "my-app", PkgbuildContent: samplePackageJSON})
	for _, id := range []string{"P-NO-CHECKSUMS", "P-SKIP-ALL", "P-WEAK-CHECKSUMS"} {
		if has(f, id) {
			t.Errorf("%s must NOT fire on a package.json; findings=%v", id, ids(f))
		}
	}
}

func TestNoChecksumsStillFiresOnRealPkgbuild(t *testing.T) {
	f := Detect(&PackageContext{Name: "foo", PkgbuildContent: samplePkgbuildNoSums})
	if !has(f, "P-NO-CHECKSUMS") {
		t.Errorf("P-NO-CHECKSUMS should still fire on a real checksum-less PKGBUILD; findings=%v", ids(f))
	}
}

func TestHTTPSourceSuppressedOnPackageJSON(t *testing.T) {
	f := Detect(&PackageContext{Name: "my-app", PkgbuildContent: samplePackageJSON})
	for _, id := range []string{"P-HTTP-SOURCE", "P-RAW-IP-URL"} {
		if has(f, id) {
			t.Errorf("%s must NOT fire on a package.json (pkgbuild-only rule); findings=%v", id, ids(f))
		}
	}
}

func TestHTTPSourceStillFiresInPkgbuild(t *testing.T) {
	f := Detect(&PackageContext{Name: "foo", PkgbuildContent: samplePkgbuildNoSums})
	if !has(f, "P-HTTP-SOURCE") {
		t.Errorf("P-HTTP-SOURCE should fire on a PKGBUILD http source=; findings=%v", ids(f))
	}
}

func TestInlineInterpreterSuppressedOnPackageJSON(t *testing.T) {
	// The "build" script carries `node -e` but package.json is not an execution
	// surface, so the dual-use signal is suppressed (this was 109 of the FPs).
	f := Detect(&PackageContext{Name: "my-app", PkgbuildContent: samplePackageJSON})
	if has(f, "G-NODE-INLINE") {
		t.Errorf("G-NODE-INLINE must NOT fire on a non-executing package.json; findings=%v", ids(f))
	}
	if IsMalicious(f) {
		t.Errorf("a benign package.json must not be judged malicious; findings=%v", ids(f))
	}
}
