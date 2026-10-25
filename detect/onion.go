package detect

import (
	"regexp"
	"strings"
)

// Tor hidden-service (.onion) detection. A package that fetches sources from or
// beacons to a .onion address is almost never legitimate: Tor hidden services
// are a common command-and-control (C2) / exfiltration channel because they
// hide the operator's infrastructure. This is factual malicious evidence (mints
// on its own).
//
// Scans the PKGBUILD/formula, install scripts, and the latest-commit diff so a
// .onion address introduced in any of them is caught (the source_url pattern
// section only ever saw the PKGBUILD).
//
// An address, not the suffix. The rule used to accept any 16-56 character label and any
// `.onion/` or `.onion:`, so it matched `strings.Contains(addr, ".onion:")` validators,
// `http://test.onion/test` and `example.onion` placeholders, `FavouriteFoodEnum.ONION`, and the
// public onion services that Tor-aware apps ship as defaults (DuckDuckGo, Ahmia, the Tor Project,
// mempool.space, Cloudflare). The 2026-10 audit replayed 74 withdrawn lines and 72 fired. A hidden
// service name is exactly 16 base32 characters (v2) or 56 ending in `d` (v3: the version byte is 3);
// placeholders made of the alphabet in order, or v3-length names that do not end in `d`, are not
// addresses. Replay: withdrawn 72 -> 20 (library 72 -> 20), real v3 addresses of Tor apps' own
// seed nodes, mirrors and test hosts that the line alone cannot tell from a C2; the verified-malware line
// (`AGENT_URL = "http://sytej5um....onion/mirai_agent.exe"`) still fires.
var onionRE = regexp.MustCompile(`(?i)\b(?:[a-z2-7]{55}d|[a-z2-7]{16})\.onion\b`)

// publicOnions are hidden services run by well-known public operators that Tor-aware software
// names as defaults: search engines, the Tor Project, block explorers, a CDN. None is a host a
// package author controls, so none can be a C2.
var publicOnions = map[string]bool{
	"duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad": true, // DuckDuckGo
	"juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd": true, // Ahmia search
	"2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid": true, // torproject.org
	"facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd": true, // Facebook
	"mempoolhqx4isw62xs7abwphsq7ldayuidyx2v2oethdhhj6mlo2r6ad": true, // mempool.space
	"cflarexljc3rw355ysrkrzwapozws6nre6xsy3n4yrj7taye3uiby3ad": true, // Cloudflare
}

// isOnionAddress reports whether a matched `<label>.onion` names a real, non-public hidden
// service: not a placeholder spelled from the base32 alphabet in order, not a public operator's.
func isOnionAddress(m string) bool {
	label := strings.TrimSuffix(strings.ToLower(m), ".onion")
	if publicOnions[label] {
		return false
	}
	return !strings.Contains(label, "abcdefghijklmn") && !strings.Contains(label, "aaaaaaaa")
}

func analyzeOnion(ctx *PackageContext) []Finding {
	for _, content := range []string{ctx.PkgbuildContent, ctx.InstallScriptContent, latestCommitDiff(ctx)} {
		if content == "" {
			continue
		}
		for _, line := range splitLines(content) {
			for _, m := range onionRE.FindAllString(line, -1) {
				if !isOnionAddress(m) {
					continue
				}
				return []Finding{{
					ID:          "P-ONION-C2",
					Category:    "source-url",
					Class:       ClassEvidence,
					CWE:         "CWE-94", // C2 channel — improper control of code/command
					Points:      65,
					Description: "Tor .onion hidden-service address (possible C2 / exfiltration endpoint)",
					MatchedLine: trimSpace(line),
				}}
			}
		}
	}
	return nil
}

// latestCommitDiff returns the unified diff of the newest commit, if collected.
func latestCommitDiff(ctx *PackageContext) string {
	if len(ctx.GitLog) > 0 {
		return ctx.GitLog[0].Diff
	}
	return ""
}
