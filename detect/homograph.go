package detect

import (
	"regexp"
	"strings"
	"unicode"
)

// IDN homograph / look-alike domain detection in package source & download URLs.
//
// A homograph attack swaps visually identical characters from another Unicode
// script into a hostname — e.g. Cyrillic "і" (U+0456) for Latin "i" — so a source
// URL that reads as install.example-cli.dev during a manual PKGBUILD review
// actually resolves to an attacker domain (іnstall.example-clі.dev →
// xn--nstall-ovf.xn--example-cl-62i.dev). Reviewers cannot see the difference;
// the build then fetches the payload from the attacker host. (Raised on
// aur-general, Jun 2026 — a review-evasion technique distinct from a typo.)
//
//   - A hostname label that MIXES letters from more than one script (Latin +
//     Cyrillic/Greek/…) has no legitimate use — IDNA and registries forbid it for
//     exactly this reason — so it is factual evidence (mints on its own).
//   - A punycode (xn--) host is the encoded form; it CAN be a legitimate
//     internationalised domain, so it is recorded as a risk signal (context) only,
//     never minting on its own.
//
// CWE-1007: Insufficient Visual Distinction of Homoglyphs Presented to User.

var urlHostRE = regexp.MustCompile("(?i)\\b(?:https?|ftp|git)://([^/\\s\"'`):]+)")

// letterScript names the Unicode script of a letter rune (for the mixed-script
// check), or "" for non-letters (digits, hyphen, dot — which carry no script).
func letterScript(r rune) string {
	switch {
	case r < 128:
		if unicode.IsLetter(r) {
			return "Latin" // ASCII letters are Latin
		}
		return ""
	case unicode.Is(unicode.Cyrillic, r):
		return "Cyrillic"
	case unicode.Is(unicode.Greek, r):
		return "Greek"
	case unicode.Is(unicode.Latin, r):
		return "Latin"
	case unicode.Is(unicode.Han, r):
		return "Han"
	case unicode.Is(unicode.Hangul, r):
		return "Hangul"
	case unicode.Is(unicode.Hiragana, r), unicode.Is(unicode.Katakana, r):
		return "Kana"
	case unicode.Is(unicode.Arabic, r):
		return "Arabic"
	case unicode.IsLetter(r):
		return "Other"
	}
	return ""
}

func analyzeHomograph(ctx *PackageContext) []Finding {
	var out []Finding
	seenMixed, seenPuny := false, false

	scan := func(content string) {
		for _, m := range urlHostRE.FindAllStringSubmatch(content, -1) {
			host := strings.ToLower(m[1])
			if !seenPuny && strings.Contains(host, "xn--") {
				seenPuny = true
				out = append(out, Finding{
					ID: "P-IDN-PUNYCODE-HOST", Category: "source-url", Class: ClassContext,
					CWE: "CWE-1007",
					Description: "IDN/punycode (xn--) host in a source/download URL — possible " +
						"homograph look-alike of a trusted domain; verify the decoded name",
					MatchedLine: host,
				})
			}
			if seenMixed {
				continue
			}
			for _, label := range strings.Split(host, ".") {
				scripts := map[string]bool{}
				for _, r := range label {
					if s := letterScript(r); s != "" {
						scripts[s] = true
					}
				}
				if len(scripts) > 1 {
					seenMixed = true
					out = append(out, Finding{
						ID: "P-HOMOGRAPH-MIXED-SCRIPT", Category: "source-url", Class: ClassEvidence,
						CWE: "CWE-1007", Points: 60,
						Description: "Mixed-script hostname label in a source/download URL — an IDN " +
							"homograph spoof (one label mixes scripts, e.g. Latin with Cyrillic, to " +
							"impersonate a trusted domain during review)",
						MatchedLine: label,
					})
					break
				}
			}
		}
	}

	for _, c := range []string{ctx.PkgbuildContent, ctx.InstallScriptContent, latestCommitDiff(ctx)} {
		if c != "" {
			scan(c)
		}
	}
	if ctx.Meta != nil {
		scan(strings.Join(ctx.Meta.Source, "\n") + "\n" + ctx.Meta.URL)
	}
	return out
}
