package detect

import (
	"regexp"
	"strings"
)

func splitLines(s string) []string { return strings.Split(s, "\n") }

func trimSpace(s string) string { return strings.TrimSpace(s) }

// pkgbuildMarkerRE matches the line-anchored bash assignments/functions that are
// unique to an Arch PKGBUILD. It deliberately anchors at line start so it never
// fires on a declarative manifest (package.json/composer.json are JSON;
// setup.py/Cargo.toml/*.gemspec use different keys) — those carry no top-level
// `pkgname=` / `source=(` / `build()`.
var pkgbuildMarkerRE = regexp.MustCompile(`(?m)^\s*(pkgname=|pkgver=|pkgrel=|arch=\(|source(_[a-z0-9]+)?=\(|(build|package|prepare|check)\s*\(\)\s*\{?)`)

// looksLikePkgbuild reports whether content is an Arch PKGBUILD (or a shell
// snippet shaped like one). PKGBUILD-only analyzers (checksum arrays, source-URL
// hygiene) gate on this so they stop emitting on npm/pypi/etc. manifests, which
// is the source of the P-NO-CHECKSUMS / P-HTTP-SOURCE false positives.
func looksLikePkgbuild(content string) bool {
	if content == "" {
		return false
	}
	return pkgbuildMarkerRE.MatchString(content)
}
