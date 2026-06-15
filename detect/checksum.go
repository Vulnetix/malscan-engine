package detect

import (
	"fmt"
	"regexp"
	"strings"
)

// Checksum analysis — port of traur src/features/checksum_analysis/mod.rs.
// Missing/weak/SKIP checksums are quality/risk signals, not proof of malice,
// so they are emitted as ClassContext (recorded as metadata, never minting).

var (
	hasChecksumsRE    = regexp.MustCompile(`(?m)^(md5|sha1|sha224|sha256|sha384|sha512|b2)sums(_[a-zA-Z0-9_]+)?\s*=`)
	weakChecksumsRE   = regexp.MustCompile(`(?m)^(md5|sha1)sums=`)
	strongChecksumsRE = regexp.MustCompile(`(?m)^(sha(256|384|512)|b2)sums=`)
	checksumArrayRE   = regexp.MustCompile(`(?ms)^(md5|sha\d+|b2)sums=\((.*?)\)`)
	entryRE           = regexp.MustCompile(`'([^']*)'`)
	tokenRE           = regexp.MustCompile(`['"][^'"]*['"]|[^\s'")()]+`)
	sourceArraySuffix = regexp.MustCompile(`(?m)^source(_[a-zA-Z0-9_]+)?\s*=\s*\(`)
	dynamicBashRE     = regexp.MustCompile(`\$\(|` + "`" + `|\$\{[^}]*\[@\]|\$\{[^}]*\[\*\]`)
)

func analyzeChecksum(ctx *PackageContext) []Finding {
	content := ctx.PkgbuildContent
	if content == "" {
		return nil
	}
	var out []Finding
	name := ctx.Name
	isVCS := strings.HasSuffix(name, "-git") || strings.HasSuffix(name, "-svn") ||
		strings.HasSuffix(name, "-hg") || strings.HasSuffix(name, "-bzr")

	if !hasChecksumsRE.MatchString(content) && !isVCS {
		out = append(out, ctxFinding("P-NO-CHECKSUMS", "pkgbuild", 30, "No checksum array found in PKGBUILD"))
	}
	if !isVCS && hasAllSkipChecksums(content) {
		out = append(out, ctxFinding("P-SKIP-ALL", "pkgbuild", 25, "All checksums are SKIP (no integrity verification)"))
	}
	if weakChecksumsRE.MatchString(content) && !strongChecksumsRE.MatchString(content) {
		out = append(out, ctxFinding("P-WEAK-CHECKSUMS", "pkgbuild", 10, "Using weak checksums (md5/sha1) without stronger alternative"))
	}

	for _, suffix := range findArraySuffixes(content) {
		srcCount := countArrayEntries(content, "source"+suffix)
		if srcCount == 0 {
			continue
		}
		for _, algo := range []string{"md5sums", "sha256sums", "sha512sums", "b2sums"} {
			cksumCount := countArrayEntries(content, algo+suffix)
			if cksumCount > 0 && cksumCount != srcCount {
				out = append(out, ctxFinding("P-CHECKSUM-MISMATCH", "pkgbuild", 25,
					fmt.Sprintf("checksum count mismatch: source%s has %d entries but %s%s has %d", suffix, srcCount, algo, suffix, cksumCount)))
				return out
			}
		}
	}
	return out
}

func hasAllSkipChecksums(content string) bool {
	found := false
	for _, caps := range checksumArrayRE.FindAllStringSubmatch(content, -1) {
		body := caps[2]
		var entries []string
		for _, e := range entryRE.FindAllStringSubmatch(body, -1) {
			entries = append(entries, e[1])
		}
		if len(entries) == 0 {
			continue
		}
		found = true
		for _, e := range entries {
			if e != "SKIP" {
				return false
			}
		}
	}
	return found
}

func findArraySuffixes(content string) []string {
	var out []string
	for _, c := range sourceArraySuffix.FindAllStringSubmatch(content, -1) {
		out = append(out, c[1])
	}
	return out
}

func countArrayEntries(content, arrayName string) int {
	re, err := regexp.Compile(`(?ms)^` + regexp.QuoteMeta(arrayName) + `=\((.*?)\)`)
	if err != nil {
		return 0
	}
	caps := re.FindStringSubmatch(content)
	if caps == nil {
		return 0
	}
	body := caps[1]
	if dynamicBashRE.MatchString(body) {
		return 0
	}
	return len(tokenRE.FindAllStringIndex(body, -1))
}

// ctxFinding builds a context Finding (recorded as metadata, never minting).
func ctxFinding(id, category string, points int, desc string) Finding {
	return Finding{ID: id, Category: category, Class: ClassContext, Points: points, Description: desc}
}
