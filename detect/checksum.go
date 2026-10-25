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
	if strings.EqualFold(strings.TrimSpace(ctx.Ecosystem), "julia") {
		return analyzeJuliaBuildDownload(ctx.InstallScriptContent)
	}
	content := ctx.PkgbuildContent
	if content == "" {
		return nil
	}
	// `*sums=()` integrity arrays are an Arch-PKGBUILD concept. Running this over a
	// declarative manifest (npm package.json, setup.py, composer.json, …) only
	// ever yields P-NO-CHECKSUMS noise, so gate it to actual PKGBUILD content.
	if !looksLikePkgbuild(content) {
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
	out = append(out, httpSourceSkip(content)...)

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

// cvssUnverifiedDownload scores fetching code over a channel an on-path attacker can rewrite,
// with nothing checking what arrived: network, high complexity (the attacker must sit on the
// path), and the build or install runs what it fetched.
const cvssUnverifiedDownload = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H"

// weaknessFinding builds a ClassWeakness Finding: a vulnerability candidate, never malware.
func weaknessFinding(id, category, cwe, cvss string, points int, desc, line string) Finding {
	return Finding{ID: id, Category: category, Class: ClassWeakness, CWE: cwe, CVSSVector: cvss,
		Points: points, Description: desc, MatchedLine: line}
}

// httpSourceSkip reports source entries fetched over plain http or ftp whose every checksum is
// SKIP: makepkg builds whatever the network returned. A weakness (CWE-494), not malice; the
// audit reclassified sundtek and janusvr to it. Entries pair by position, per source array
// suffix (source_x86_64 with sha256sums_x86_64). A checksum array that cannot be read statically
// ($(...), ${arr[@]}) is skipped.
func httpSourceSkip(content string) []Finding {
	for _, suffix := range findArraySuffixes(content) {
		srcs := arrayEntries(content, "source"+suffix)
		if len(srcs) == 0 {
			continue
		}
		var sums [][]string
		for _, algo := range []string{"md5sums", "sha1sums", "sha224sums", "sha256sums", "sha384sums", "sha512sums", "b2sums"} {
			if e := arrayEntries(content, algo+suffix); e != nil {
				if len(e) != len(srcs) {
					sums = nil // P-CHECKSUM-MISMATCH's case; the pairing is unknown
					break
				}
				sums = append(sums, e)
			}
		}
		if len(sums) == 0 {
			continue
		}
		for i, s := range srcs {
			u := s
			if j := strings.Index(u, "::"); j >= 0 {
				u = u[j+2:]
			}
			lu := strings.ToLower(u)
			if !strings.HasPrefix(lu, "http://") && !strings.HasPrefix(lu, "ftp://") {
				continue
			}
			skipped := true
			for _, e := range sums {
				if e[i] != "SKIP" {
					skipped = false
					break
				}
			}
			if skipped {
				return []Finding{weaknessFinding("P-HTTP-SOURCE-SKIP", "pkgbuild", "CWE-494", cvssUnverifiedDownload, 30,
					"Source fetched over plain http/ftp with a SKIP checksum (no integrity check)", u)}
			}
		}
	}
	return nil
}

// arrayEntries returns the unquoted entries of a bash array assignment, or nil when it is absent
// or built dynamically.
func arrayEntries(content, arrayName string) []string {
	re, err := regexp.Compile(`(?ms)^` + regexp.QuoteMeta(arrayName) + `=\((.*?)\)`)
	if err != nil {
		return nil
	}
	caps := re.FindStringSubmatch(content)
	if caps == nil || dynamicBashRE.MatchString(caps[1]) {
		return nil
	}
	var out []string
	for _, line := range strings.Split(caps[1], "\n") {
		if i := strings.Index(line, "#"); i >= 0 && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t') {
			line = line[:i]
		}
		for _, t := range tokenRE.FindAllString(line, -1) {
			out = append(out, strings.Trim(t, `'"`))
		}
	}
	if out == nil {
		out = []string{}
	}
	return out
}

var (
	// juliaDownloadRE is a fetch in a Julia build script: download()/Downloads.download(), a
	// curl/wget command literal, BinDeps' FileDownloader, or a PowerShell DownloadFile.
	juliaDownloadRE = regexp.MustCompile("(?:^|[^A-Za-z0-9_])download\\s*\\(|`\\s*(?:curl|wget)\\s|FileDownloader\\s*\\(|DownloadFile\\s*\\(")
	juliaHTTPURLRE  = regexp.MustCompile(`["'\x60\s(]http://[^\s"'\x60)]+`)
	// juliaHashRE is any sign the script checks what it fetched.
	juliaHashRE = regexp.MustCompile(`(?i)sha-?(?:1|256|512)|\bmd5\b|checksum|hash\s*\(|bytes2hex|verify`)
)

// analyzeJuliaBuildDownload judges a Julia package's deps/build.jl downloads. Fetching a
// dependency at Pkg.build time is how pre-artifact Julia packages got their libraries (14 of the
// 21 audited JULIA mints were withdrawn as normal build logic), so a download is context. Over plain
// http with nothing verifying it, it is a CWE-494 weakness: the shape of all five reclassified
// build.jl files (ArbFloats, CQLdriver, Concorde, GMT, LKH).
func analyzeJuliaBuildDownload(script string) []Finding {
	if script == "" {
		return nil
	}
	var dl, httpLine string
	for _, raw := range splitLines(script) {
		line := trimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if dl == "" && juliaDownloadRE.MatchString(line) {
			dl = line
		}
		if httpLine == "" && juliaHTTPURLRE.MatchString(line) {
			httpLine = line
		}
	}
	if dl == "" {
		return nil
	}
	if httpLine != "" && !juliaHashRE.MatchString(script) {
		return []Finding{weaknessFinding("JL-BUILD-UNVERIFIED-DOWNLOAD", "install", "CWE-494", cvssUnverifiedDownload, 40,
			"build.jl downloads over plain http and verifies no checksum before building or running it", httpLine)}
	}
	f := ctxFinding("JL-BUILD-DOWNLOAD", "install", 15, "build.jl downloads a dependency at Pkg.build time")
	f.MatchedLine = dl
	return []Finding{f}
}

// ctxFinding builds a context Finding (recorded as metadata, never minting).
func ctxFinding(id, category string, points int, desc string) Finding {
	return Finding{ID: id, Category: category, Class: ClassContext, Points: points, Description: desc}
}
