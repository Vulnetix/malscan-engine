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

// confusableMix reports whether a label mixes Latin, Cyrillic and Greek, the scripts whose
// letters are visually interchangeable. CJK, Arabic and Hangul beside Latin are ordinary
// internationalised names (or prose that ran into a URL), not a spoof.
func confusableMix(scripts map[string]bool) bool {
	n := 0
	for _, s := range []string{"Latin", "Cyrillic", "Greek"} {
		if scripts[s] {
			n++
		}
	}
	return n > 1
}

// hostLabelRE is one hostname label: letters (any script), digits and inner hyphens.
var hostLabelRE = regexp.MustCompile(`^[\p{L}\p{N}](?:[\p{L}\p{N}-]*[\p{L}\p{N}])?$`)

// tldRE is a top-level label: letters only (any script), or an IDNA xn-- label.
var tldRE = regexp.MustCompile(`^(?:\p{L}{2,63}|xn--[a-z0-9-]{2,59})$`)

// urlHostname returns the hostname part of a captured URL authority when it is a real dotted
// domain name with a TLD, or "" otherwise. A template placeholder (`<домен-signal-hunt>`,
// `{host}`, `$HOST`), a single label (`localhost`) or a bare IP is not a domain a homograph can
// impersonate. Audited 2026-10: `https://<домен-signal-hunt>/…` in a pypi tool's usage text
// minted as a Cyrillic/Latin mixed label.
func urlHostname(authority string) string {
	h := authority
	if i := strings.LastIndexByte(h, '@'); i >= 0 {
		h = h[i+1:]
	}
	// Sentence punctuation after a URL is not part of the host.
	h = strings.TrimRight(strings.ToLower(h), ".,;!?]}>")
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return ""
	}
	for _, l := range labels {
		if !hostLabelRE.MatchString(l) {
			return ""
		}
	}
	if !tldRE.MatchString(labels[len(labels)-1]) {
		return ""
	}
	return h
}

func analyzeHomograph(ctx *PackageContext) []Finding {
	var out []Finding
	seenMixed, seenPuny := false, false

	scan := func(content, surface string) {
		for _, line := range splitLines(content) {
			scanLine(line, surface, &out, &seenMixed, &seenPuny)
		}
	}

	pkgSurface := SurfaceLibrary
	if ctx.PkgbuildExecutes {
		pkgSurface = SurfaceBuild
	}
	for _, c := range []struct{ content, surface string }{
		{ctx.PkgbuildContent, pkgSurface},
		{ctx.InstallScriptContent, SurfaceInstall},
		{latestCommitDiff(ctx), ""},
	} {
		if c.content != "" {
			scan(c.content, c.surface)
		}
	}
	if ctx.Meta != nil {
		scan(strings.Join(ctx.Meta.Source, "\n")+"\n"+ctx.Meta.URL, "")
	}
	return out
}

// scanLine judges the URL hosts on one line. A mixed-script label is evidence only on a line
// the comment guard and the per-rule suppressors (suppressLine) keep: documentation ABOUT a
// spoof is not one.
func scanLine(line, surface string, out *[]Finding, seenMixed, seenPuny *bool) {
	ms := urlHostRE.FindAllStringSubmatch(line, -1)
	if len(ms) == 0 {
		return
	}
	guarded := suppressLine("P-HOMOGRAPH-MIXED-SCRIPT", trimSpace(line))
	for _, m := range ms {
		host := urlHostname(m[1])
		if host == "" {
			continue
		}
		if !*seenPuny && strings.Contains(host, "xn--") {
			*seenPuny = true
			*out = append(*out, Finding{
				ID: "P-IDN-PUNYCODE-HOST", Category: "source-url", Class: ClassContext,
				CWE: "CWE-1007",
				Description: "IDN/punycode (xn--) host in a source/download URL — possible " +
					"homograph look-alike of a trusted domain; verify the decoded name",
				MatchedLine: host,
				Surface:     surface,
			})
		}
		if *seenMixed || guarded {
			continue
		}
		for _, label := range strings.Split(host, ".") {
			scripts := map[string]bool{}
			for _, r := range label {
				if s := letterScript(r); s != "" {
					scripts[s] = true
				}
			}
			// Only scripts that can impersonate Latin letters make a spoof. Latin beside Han
			// is what the host regex produces from `com（否则` -- a URL followed by CJK
			// prose and a full-width bracket -- and 157 pypi/cargo/go/packagist/pubdev
			// mints carried this rule with none OpenSSF-confirmed.
			if len(scripts) > 1 && confusableMix(scripts) {
				*seenMixed = true
				*out = append(*out, Finding{
					ID: "P-HOMOGRAPH-MIXED-SCRIPT", Category: "source-url", Class: ClassEvidence,
					CWE: "CWE-1007", Points: 60,
					Description: "Mixed-script hostname label in a source/download URL — an IDN " +
						"homograph spoof (one label mixes scripts, e.g. Latin with Cyrillic, to " +
						"impersonate a trusted domain during review)",
					MatchedLine: label,
					Surface:     surface,
				})
				break
			}
		}
	}
}
