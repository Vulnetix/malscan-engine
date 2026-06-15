package detect

import (
	"fmt"
	"regexp"
	"strings"
)

// Temporal analysis — port of traur git_history_analysis + pkgbuild_diff_analysis.
// Malicious-diff and newly-introduced-suspicious-pattern are factual evidence;
// commit-count / package-age / author-change / major-rewrite are risk context.

var (
	netDiffRE    = regexp.MustCompile(`\+.*(curl|wget|nc\s|ncat|socat|/dev/tcp|python.*socket|ruby.*socket)`)
	netContentRE = regexp.MustCompile(`(curl|wget|nc\s|ncat|socat|/dev/tcp|python.*socket|ruby.*socket)`)

	diffChecksumRE = regexp.MustCompile(`(?m)^(md5|sha1|sha224|sha256|sha384|sha512|b2)sums(_[a-z0-9_]+)?=`)
	diffSourceRE   = regexp.MustCompile(`(?m)^source(_[a-z0-9_]+)?\s*=\s*\(([^)]*)\)`)
	urlDomainRE    = regexp.MustCompile(`https?://([^/\s'"]+)`)
)

func analyzeGitHistory(ctx *PackageContext) []Finding {
	if len(ctx.GitLog) == 0 {
		return nil
	}
	var out []Finding
	now := nowUnix()

	if len(ctx.GitLog) == 1 {
		out = append(out, ctxFinding("T-SINGLE-COMMIT", "temporal", 20, "Git history has only 1 commit"))
	}

	var created int64
	if ctx.Meta != nil && ctx.Meta.FirstSubmitted > 0 {
		created = ctx.Meta.FirstSubmitted
	} else if len(ctx.GitLog) > 0 {
		created = ctx.GitLog[len(ctx.GitLog)-1].Timestamp
	}
	if created > 0 && now > created {
		ageDays := (now - created) / 86400
		if ageDays < 7 {
			out = append(out, ctxFinding("T-NEW-PACKAGE", "temporal", 25,
				fmt.Sprintf("Package is very new (%d days old)", ageDays)))
		}
	}

	newest := ctx.GitLog[0]
	if newest.Diff != "" && netDiffRE.MatchString(newest.Diff) {
		hasPriorNet := ctx.PriorPkgbuildContent != "" && netContentRE.MatchString(ctx.PriorPkgbuildContent)
		if !hasPriorNet {
			out = append(out, finding("T-MALICIOUS-DIFF", "temporal", 55,
				"Latest commit introduces network code not present in prior history"))
		}
	}

	if len(ctx.GitLog) >= 2 {
		seen := map[string]bool{}
		for _, c := range ctx.GitLog {
			seen[c.Author] = true
		}
		if len(seen) > 1 {
			out = append(out, ctxFinding("T-AUTHOR-CHANGE", "temporal", 25, "Git history shows multiple different authors"))
		}
	}
	return out
}

func analyzePkgbuildDiff(ctx *PackageContext) []Finding {
	newC, oldC := ctx.PkgbuildContent, ctx.PriorPkgbuildContent
	if newC == "" || oldC == "" {
		return nil
	}
	loadPatterns()
	var out []Finding

	// New high-severity (>=60) pattern not present in the old PKGBUILD.
	for _, p := range patternsBySection["pkgbuild_analysis"] {
		if p.points < 60 {
			continue
		}
		if p.re.MatchString(newC) && !p.re.MatchString(oldC) {
			out = append(out, Finding{
				ID: "T-DIFF-NEW-SUSPICIOUS", Category: "temporal", Class: ClassEvidence,
				CWE: cweForSignal(p.id), Points: 40,
				Description: fmt.Sprintf("Newly introduced suspicious pattern: %s (%s)", p.id, p.description),
				MatchedLine: firstMatchingLine(newC, p.re),
			})
			break
		}
	}

	// Checksums removed or all changed to SKIP.
	oldHasCk := diffChecksumRE.MatchString(oldC)
	newHasCk := diffChecksumRE.MatchString(newC)
	if oldHasCk && !newHasCk {
		out = append(out, finding("T-DIFF-CHECKSUM-REMOVED", "temporal", 35, "Checksum array removed in latest update"))
	} else if oldHasCk && newHasCk {
		if !hasOnlySkipChecksums(oldC) && hasOnlySkipChecksums(newC) {
			out = append(out, finding("T-DIFF-CHECKSUM-REMOVED", "temporal", 35, "All checksums changed to SKIP in latest update"))
		}
	}

	// Source domain changed to new domain(s).
	oldDomains := extractSourceDomains(oldC)
	newDomains := extractSourceDomains(newC)
	if len(oldDomains) > 0 && len(newDomains) > 0 {
		var added []string
		for d := range newDomains {
			if !oldDomains[d] {
				added = append(added, d)
			}
		}
		if len(added) > 0 {
			out = append(out, finding("T-DIFF-SOURCE-DOMAIN-CHANGED", "temporal", 30,
				"Source URLs changed to new domain(s): "+strings.Join(added, ", ")))
		}
	}

	// >50% of lines changed.
	out = append(out, checkMajorRewrite(newC, oldC)...)
	return out
}

func hasOnlySkipChecksums(content string) bool {
	locs := diffChecksumRE.FindAllStringIndex(content, -1)
	for _, loc := range locs {
		rest := content[loc[1]:]
		_, afterParen, ok := strings.Cut(rest, "(")
		if !ok {
			continue
		}
		arrayContent, _, ok := strings.Cut(afterParen, ")")
		if !ok {
			continue
		}
		var entries []string
		for f := range strings.FieldsSeq(arrayContent) {
			f = strings.Trim(f, "'\"")
			if f != "" {
				entries = append(entries, f)
			}
		}
		if len(entries) == 0 {
			continue
		}
		allSkip := true
		for _, e := range entries {
			if e != "SKIP" {
				allSkip = false
				break
			}
		}
		if allSkip {
			continue
		}
		return false
	}
	return true
}

func extractSourceDomains(content string) map[string]bool {
	domains := map[string]bool{}
	for _, cap := range diffSourceRE.FindAllStringSubmatch(content, -1) {
		arrayContent := cap[2]
		for _, um := range urlDomainRE.FindAllStringSubmatch(arrayContent, -1) {
			d := strings.ToLower(um[1])
			if !strings.Contains(d, "$") {
				domains[d] = true
			}
		}
	}
	return domains
}

func checkMajorRewrite(newC, oldC string) []Finding {
	oldLines := nonEmptyTrimmedSet(oldC)
	newLines := nonEmptyTrimmedSet(newC)
	if len(oldLines) == 0 {
		return nil
	}
	common := 0
	for l := range oldLines {
		if newLines[l] {
			common++
		}
	}
	total := max(len(oldLines), len(newLines))
	changedPct := int(float64(total-common) / float64(total) * 100.0)
	if changedPct > 50 {
		return []Finding{ctxFinding("T-DIFF-MAJOR-REWRITE", "temporal", 15,
			fmt.Sprintf("%d%% of PKGBUILD lines changed (unusual for version bump)", changedPct))}
	}
	return nil
}

func nonEmptyTrimmedSet(s string) map[string]bool {
	set := map[string]bool{}
	for _, l := range splitLines(s) {
		t := strings.TrimSpace(l)
		if t != "" {
			set[t] = true
		}
	}
	return set
}
