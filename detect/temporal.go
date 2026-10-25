package detect

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Temporal analysis — port of traur git_history_analysis + pkgbuild_diff_analysis.
// Malicious-diff and newly-introduced-suspicious-pattern are factual evidence;
// commit-count / package-age / author-change / major-rewrite are risk context.

var (
	// A network tool as a WORD. `nc\s` with no left boundary matched "once ", "function ", "sync ",
	// "since ": any commit adding a line with one of those introduced "network code" (468 AUR advisories
	// rested on T-MALICIOUS-DIFF).
	netDiffRE    = regexp.MustCompile(`\+(?:.*[^A-Za-z0-9_])?(?:curl|wget|nc|ncat|socat)\s|\+.*(?:/dev/tcp|python.*socket|ruby.*socket)`)
	netContentRE = regexp.MustCompile(`(?:^|[^A-Za-z0-9_])(?:curl|wget|nc|ncat|socat)\s|/dev/tcp|python.*socket|ruby.*socket`)

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
			// Context, not evidence: an update that starts to fetch something is how a package
			// grows a new source or helper. What the fetch DOES is judged by the download-and-execute
			// rules; this note only corroborates them.
			out = append(out, ctxFinding("T-MALICIOUS-DIFF", "temporal", 35,
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
	// A PKGBUILD whose remaining sources are all VCS checkouts or local files has nothing a
	// checksum could pin: makepkg requires SKIP for a git+ source, and dropping the last local
	// patch takes its checksum entry with it. 8 audited AUR mints rested on exactly that
	// (4 switches to git+ sources, 4 dropped patches merged upstream).
	oldHasCk := diffChecksumRE.MatchString(oldC)
	newHasCk := diffChecksumRE.MatchString(newC)
	pinnable := hasPinnableSource(newC)
	if oldHasCk && !newHasCk && pinnable {
		out = append(out, finding("T-DIFF-CHECKSUM-REMOVED", "temporal", 35, "Checksum array removed in latest update"))
	} else if oldHasCk && newHasCk && pinnable {
		if !hasOnlySkipChecksums(oldC) && hasOnlySkipChecksums(newC) {
			out = append(out, finding("T-DIFF-CHECKSUM-REMOVED", "temporal", 35, "All checksums changed to SKIP in latest update"))
		}
	}

	// Source domain changed to new domain(s). A move between hosts of the same registrable
	// domain or within one hosting service is how upstreams relocate (pypi.python.org to
	// files.pythonhosted.org, github.com to codeload.github.com, a sourceforge mirror): 92 of the
	// 814 audited set-A AUR mints were such moves.
	oldDomains := extractSourceDomains(oldC)
	newDomains := extractSourceDomains(newC)
	if len(oldDomains) > 0 && len(newDomains) > 0 {
		oldSites := map[string]bool{}
		for d := range oldDomains {
			oldSites[sourceSite(d)] = true
		}
		var added []string
		for d := range newDomains {
			if !oldDomains[d] && !oldSites[sourceSite(d)] {
				added = append(added, d)
			}
		}
		sort.Strings(added)
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

// hostingServices maps the hosts of one code-hosting or package service to one site. A source
// that moves between them stays with the same publisher's account on the same service.
var hostingServices = map[string]string{
	"github.com": "github", "codeload.github.com": "github", "raw.githubusercontent.com": "github",
	"objects.githubusercontent.com": "github", "api.github.com": "github",
	"sourceforge.net": "sourceforge", "sf.net": "sourceforge",
	"pypi.python.org": "pypi", "pypi.org": "pypi", "pypi.io": "pypi", "files.pythonhosted.org": "pypi",
	"pythonhosted.org": "pypi",
	"gitlab.com":       "gitlab", "registry.gitlab.com": "gitlab",
	"repo.maven.apache.org": "maven", "repo1.maven.org": "maven", "central.maven.org": "maven",
	"search.maven.org": "maven",
	"cpan.org":         "cpan", "metacpan.org": "cpan", "cpan.metacpan.org": "cpan", "search.cpan.org": "cpan",
	"search.mcpan.org": "cpan", "www.cpan.org": "cpan",
}

// sourceSite names the site a source host belongs to: its hosting service when it is one of
// hostingServices (sourceforge mirrors such as phoenixnap.dl.sourceforge.net included), else
// its registrable domain.
func sourceSite(host string) string {
	h := strings.ToLower(host)
	if i := strings.Index(h, ":"); i >= 0 {
		h = h[:i]
	}
	if s, ok := hostingServices[h]; ok {
		return s
	}
	reg := registrableDomain(h)
	if s, ok := hostingServices[reg]; ok && reg != "github.com" {
		// *.sourceforge.net mirrors, *.metacpan.org. Not *.github.com: gist and pages hosts there
		// are other people's content.
		return s
	}
	return reg
}

// vcsSourceRE matches a VCS source entry, optionally after a `name::` rename.
var vcsSourceRE = regexp.MustCompile(`^(?:[^:/]+::)?(?:git|svn|hg|bzr|fossil)(?:\+|://)`)

// hasPinnableSource reports whether any source entry is a non-VCS download, the only kind a
// checksum can pin. A variable whose value is unknown (`${url}/v$pkgver.tar.gz`) counts as one.
func hasPinnableSource(content string) bool {
	for _, caps := range binSourceArraysRE.FindAllStringSubmatch(content, -1) {
		for _, tc := range binURLTokenRE.FindAllStringSubmatch(caps[1], -1) {
			raw := tc[1]
			if raw == "" {
				raw = tc[2]
			}
			if raw == "" || strings.HasPrefix(raw, "#") {
				continue
			}
			if vcsSourceRE.MatchString(raw) {
				continue
			}
			if strings.Contains(raw, "://") || strings.Contains(raw, "$") {
				return true
			}
		}
	}
	return false
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
