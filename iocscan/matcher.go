package iocscan

import (
	"bytes"
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/vulnetix/malscan-engine/detect"
)

// Matcher matches text or binary content against a preloaded IndicatorSet,
// returning Evidence. It carries no filesystem state, so a caller can build one
// IndicatorSet (via FeedLoader.Load) and reuse the Matcher across many in-memory
// scans — e.g. a registry processor matching every package's source against the
// known-bad feed without re-reading or re-parsing the feed per package.
//
// The filesystem Scan uses a Matcher internally, so both paths share identical
// matching, evidence shape, and dedup behaviour.
type Matcher struct {
	set          *IndicatorSet
	contextLines int
}

// NewMatcher returns a Matcher over set. contextLines is how many lines of file
// content to capture above and below a text hit; <= 0 uses DefaultContextLines.
func NewMatcher(set *IndicatorSet, contextLines int) *Matcher {
	if contextLines <= 0 {
		contextLines = DefaultContextLines
	}
	return &Matcher{set: set, contextLines: contextLines}
}

// Set returns the underlying indicator set.
func (m *Matcher) Set() *IndicatorSet { return m.set }

// MatchText scans text content line-by-line and returns evidence with line
// numbers and context lines. name is recorded as the evidence FilePath/RelPath
// (a logical filename when there is no real path).
func (m *Matcher) MatchText(name, content string) []Evidence {
	return m.matchText(name, name, content)
}

// MatchBytes scans raw bytes: ELF / NUL-containing input is treated as binary
// (printable strings are extracted and matched, IsBinary evidence with a byte
// offset); anything else is matched as text.
func (m *Matcher) MatchBytes(name string, data []byte) []Evidence {
	return m.matchBytes(name, name, data)
}

// matchText is the shared text matcher. filePath/relPath are recorded on the
// evidence (the filesystem walker passes an absolute path + repo-relative path;
// the in-memory API passes the same logical name for both).
func (m *Matcher) matchText(filePath, relPath, content string) []Evidence {
	tier := iocFileTier(relPath)
	if tier == tierSuppress {
		return nil
	}
	lines := splitLinesString(content)
	skipIPFile := suppressIPv4ForFile(relPath)
	var ev []Evidence
	for i, line := range lines {
		minified := isMinifiedLine(line)
		// The file-level tier sets the floor; a minified line inside an otherwise
		// kept file is generated-bundle noise, so its URL/domain hits demote to
		// context too (its IPv4 is already suppressed via skipIPv4 below).
		class := tierClass(tier)
		if class == "" && minified {
			class = detect.ClassContext
		}
		for _, mm := range m.matchLine(line, skipIPFile || minified) {
			ev = append(ev, Evidence{
				IndicatorType:  mm.typ,
				IndicatorValue: mm.value,
				Indicator:      mm.ind,
				FilePath:       filePath,
				RelPath:        relPath,
				Class:          class,
				LineNumber:     i + 1,
				ColStart:       mm.col,
				ColEnd:         mm.col + len(mm.value),
				MatchedLine:    line,
				ContextBefore:  contextBefore(lines, i, m.contextLines),
				ContextAfter:   contextAfter(lines, i, m.contextLines),
			})
		}
	}
	return ev
}

// matchBytes dispatches to the binary or text matcher based on a content sniff.
func (m *Matcher) matchBytes(filePath, relPath string, data []byte) []Evidence {
	if isBinary(data) {
		return m.matchBinary(filePath, relPath, data)
	}
	return m.matchText(filePath, relPath, string(data))
}

// matchBinary extracts printable strings from a binary and matches IOCs in them,
// deduplicating across the whole file.
func (m *Matcher) matchBinary(filePath, relPath string, data []byte) []Evidence {
	tier := iocFileTier(relPath)
	if tier == tierSuppress {
		return nil
	}
	class := tierClass(tier)
	seen := map[string]bool{}
	var ev []Evidence
	for _, sh := range extractStrings(data, stringMinLen) {
		// Binary string extraction keeps IPv4 matching — a hardcoded address in
		// an ELF/agent is a real indicator, not minified-source noise.
		for _, mm := range m.matchLine(sh.value, false) {
			key := string(mm.typ) + "|" + strings.ToLower(mm.value)
			if seen[key] {
				continue
			}
			seen[key] = true
			ev = append(ev, Evidence{
				IndicatorType:  mm.typ,
				IndicatorValue: mm.value,
				Indicator:      mm.ind,
				FilePath:       filePath,
				RelPath:        relPath,
				IsBinary:       true,
				Class:          class,
				ByteOffset:     sh.offset + int64(mm.col),
				MatchedLine:    truncate(sh.value, 200),
			})
		}
	}
	return ev
}

// ── Matching core ───────────────────────────────────────────────────────────

type lineMatch struct {
	typ   IndicatorType
	value string
	col   int
	ind   *Indicator
}

var (
	urlRe    = regexp.MustCompile("(?i)\\bhttps?://[^\\s'\"`<>)\\]}\\\\]+")
	domainRe = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b`)
	ipv4Re   = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	ipv6Re   = regexp.MustCompile(`(?i)\b[0-9a-f:]{4,45}\b`)
)

// matchLine finds every known-bad indicator referenced in s, deduplicated by
// (type, value). It is used both line-by-line over text and over strings
// extracted from binaries. skipIPv4 suppresses bare-IPv4 matching for lines /
// files whose dense numeric content (minified bundles, source maps, SVG
// coordinates) collides with IP octets without ever referencing an address.
func (m *Matcher) matchLine(s string, skipIPv4 bool) []lineMatch {
	var matches []lineMatch
	seen := map[string]bool{}
	add := func(typ IndicatorType, value string, col int, ind *Indicator) {
		key := string(typ) + "|" + strings.ToLower(value)
		if seen[key] {
			return
		}
		seen[key] = true
		matches = append(matches, lineMatch{typ: typ, value: value, col: col, ind: ind})
	}

	// URLs (and the domain inside them).
	for _, loc := range urlRe.FindAllStringIndex(s, -1) {
		u := s[loc[0]:loc[1]]
		if ind := m.set.LookupURL(u); ind != nil {
			add(TypeURL, u, loc[0], ind)
		}
		if host := urlHost(u); host != "" {
			if ind := m.set.LookupDomain(host); ind != nil {
				col := loc[0]
				if idx := strings.Index(strings.ToLower(u), strings.ToLower(host)); idx >= 0 {
					col += idx
				}
				add(TypeDomain, host, col, ind)
			}
		}
	}

	// Bare domains.
	for _, loc := range domainRe.FindAllStringIndex(s, -1) {
		dom := strings.TrimSuffix(s[loc[0]:loc[1]], ".")
		if ind := m.set.LookupDomain(dom); ind != nil {
			add(TypeDomain, dom, loc[0], ind)
		}
	}

	// IPv4 — only when the token is actually used as an address. It must be a
	// canonical dotted-quad (strictIPv4: four octets 0-255, no leading zeros) and
	// be delimited by non-numeric characters (ipBoundaryOK), so a longer dotted
	// run (a 1.2.3.4.5 version), a signed coordinate (-1.2.3.4) or a range
	// (1.2.3.4-5) is rejected rather than matched as an IP. skipIPv4 drops the
	// whole branch for generated/minified content (see suppressIPv4ForFile /
	// isMinifiedLine) where IP-shaped numeric noise is pervasive.
	if !skipIPv4 {
		for _, loc := range ipv4Re.FindAllStringIndex(s, -1) {
			if !ipBoundaryOK(s, loc[0], loc[1]) {
				continue
			}
			// Reject only tokens that were never an address — a literal that a real
			// C2 could not inhabit. Anything that COULD be a malicious endpoint
			// (including IPv4-mapped IPv6 like ::ffff:1.2.3.4) is kept for matching.
			if ipv4InSlashVersion(s, loc[0]) || ipv4InSVGGeometry(s, loc[0]) {
				continue
			}
			ipStr := s[loc[0]:loc[1]]
			if !strictIPv4(ipStr) {
				continue
			}
			if ind := m.set.LookupIP(ipStr); ind != nil {
				add(TypeIPv4, ipStr, loc[0], ind)
			}
		}
	}

	// IPv6 (permissive candidate, validated by net.ParseIP).
	for _, loc := range ipv6Re.FindAllStringIndex(s, -1) {
		ipStr := s[loc[0]:loc[1]]
		if strings.Count(ipStr, ":") < 2 {
			continue
		}
		if ip := net.ParseIP(ipStr); ip != nil && ip.To4() == nil {
			if ind := m.set.LookupIP(ipStr); ind != nil {
				add(TypeIPv6, ipStr, loc[0], ind)
			}
		}
	}

	return matches
}

// ipBoundaryOK reports whether the IPv4 candidate s[start:end] is delimited by
// non-numeric characters on both sides — i.e. it is not part of a longer dotted
// or signed number run. Adjacent letters are already excluded by the \b in the
// regex; this additionally rejects the number-context delimiters '.', '+', '-'
// and digits, so 1.2.3.4.5 (version), -1.2.3.4 (coordinate) and 1.2.3.4-9
// (range) are not mistaken for an address.
func ipBoundaryOK(s string, start, end int) bool {
	if start > 0 && isNumBoundary(s[start-1]) {
		return false
	}
	if end < len(s) && isNumBoundary(s[end]) {
		return false
	}
	return true
}

func isNumBoundary(c byte) bool {
	return c == '.' || c == '+' || c == '-' || (c >= '0' && c <= '9')
}

// ipv4InSlashVersion reports whether the dotted-quad at s[start:] is the version
// part of a "<word>/<quad>" token — "Chrome/119.0.0.0", "Safari/537.36" in a
// User-Agent, or a "<path>/1.2.3.4" URL path segment. A quad bound to a word by a
// single '/' is a software version or path component, never a connected network
// endpoint, so it can never be a C2/exfil indicator and is dropped.
//
// This is deliberately narrow: a real URL host ("http://1.2.3.4") is preceded by
// "//" — the char before the '/' is '/', not a letter — so it is NOT rejected,
// and its full URL still matches via the url/domain branches regardless. An
// IPv4-mapped IPv6 literal ("::ffff:1.2.3.4") is also untouched: it embeds a real
// address that a real C2 could use, so it stays matchable.
func ipv4InSlashVersion(s string, start int) bool {
	return start >= 2 && s[start-1] == '/' && isASCIILetter(s[start-2])
}

func isASCIILetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// svgGeometryAttrs open an SVG vector-geometry attribute whose value is pure
// path/coordinate data — numbers and path-command letters, never a network
// endpoint. Both the unescaped (`d="`) and JSON/JS-escaped (`d=\"`) forms are
// listed because icon packs ship SVG inside JSON/JS string literals (the
// @iconify/json bodies are `"<path d=\"M…\"/>"`). Attributes that CAN carry a
// real address (`onload=`, `xlink:href=`, `style=`) are intentionally absent, so
// an IP smuggled into a scripted SVG is still matched.
var svgGeometryAttrs = []string{
	`d="`, `d='`, `d=\"`,
	`points="`, `points='`, `points=\"`,
	`transform="`, `transform='`, `transform=\"`,
}

// ipv4InSVGGeometry reports whether the dotted-quad at s[start:] sits inside an
// SVG geometry attribute value (`d`, `points`, `transform`). Such values pack
// adjacent coordinates with no separators ("c.67 0 1.15.65.96 1.29z"), and the
// IPv4 regex splices three of them into a quad (1.15.65.96 = 1.15 / .65 / .96)
// that was never an address — the canonical @iconify/json false positive. Because
// geometry values contain no quotes, the candidate is "inside" the value when the
// nearest geometry-attribute opener before it has no quote between it and the
// candidate; a real IP in any other attribute on the same element has the
// attribute's closing quote in between and is therefore still matched.
func ipv4InSVGGeometry(s string, start int) bool {
	pre := s[:start]
	open := -1 // end index of the nearest boundary-anchored geometry opener
	for _, attr := range svgGeometryAttrs {
		for from := 0; ; {
			i := strings.Index(pre[from:], attr)
			if i < 0 {
				break
			}
			idx := from + i
			from = idx + 1
			// The attribute name must start at a separator, else this is the tail
			// of a longer name (the "d=\"" inside onload="…", id="…", download="…").
			if idx > 0 && pre[idx-1] != ' ' && pre[idx-1] != '\t' {
				continue
			}
			if end := idx + len(attr); end > open {
				open = end
			}
		}
	}
	if open < 0 {
		return false
	}
	// A quote between the opener and the candidate means that geometry value
	// already closed — the candidate lives in some later, non-geometry context.
	return !strings.ContainsAny(s[open:start], `"'`)
}

// strictIPv4 reports whether ipStr is a canonical dotted-quad: exactly four
// octets, each a 1-3 digit number 0-255 with no leading zeros. This rejects
// coordinate / version tokens that are not real addresses and the octal-style
// leading-zero forms net.ParseIP is lenient about across Go versions.
func strictIPv4(ipStr string) bool {
	octets := 0
	i := 0
	for octets < 4 {
		octets++
		j := i
		for j < len(ipStr) && ipStr[j] >= '0' && ipStr[j] <= '9' {
			j++
		}
		n := j - i
		if n == 0 || n > 3 {
			return false
		}
		if n > 1 && ipStr[i] == '0' { // leading zero
			return false
		}
		v := 0
		for k := i; k < j; k++ {
			v = v*10 + int(ipStr[k]-'0')
		}
		if v > 255 {
			return false
		}
		i = j
		if octets < 4 {
			if i >= len(ipStr) || ipStr[i] != '.' {
				return false
			}
			i++ // consume the dot
		}
	}
	return i == len(ipStr)
}

// noisyIPv4Suffixes are file types whose content is dense IP-shaped numeric data
// (vector coordinates, source-map mappings/embedded source, minified bundles)
// that collides with IP octets but never references an address. Bare-IPv4
// matching is suppressed for them; domain/URL matching (which carries TLD/scheme
// signal) is unaffected.
var noisyIPv4Suffixes = []string{".svg", ".map", ".min.js", ".min.mjs", ".min.cjs", ".min.css"}

// suppressIPv4ForFile reports whether bare-IPv4 matching should be skipped for a
// file based on its path/extension.
func suppressIPv4ForFile(relPath string) bool {
	p := strings.ToLower(relPath)
	for _, suf := range noisyIPv4Suffixes {
		if strings.HasSuffix(p, suf) {
			return true
		}
	}
	return false
}

// inertDocSuffixes are documentation formats that are never executed and never
// fetched as part of a package's runtime/install — Markdown in its common
// extensions. An IP/domain/URL in inert docs (a README's example endpoint, a
// CHANGELOG link, an API sample) is documentation, not an indicator of compromise.
var inertDocSuffixes = []string{".md", ".markdown", ".mdx", ".mkd", ".mdown"}

// isInertDoc reports whether relPath is inert documentation whose IOC references
// must not be raised as malware findings (see inertDocSuffixes). Only Markdown is
// listed: source maps, minified bundles and test fixtures are NOT inert — they can
// carry a real, executed payload — so they stay scanned.
func isInertDoc(relPath string) bool {
	p := strings.ToLower(relPath)
	for _, suf := range inertDocSuffixes {
		if strings.HasSuffix(p, suf) {
			return true
		}
	}
	return false
}

// ── IOC context tiering ──────────────────────────────────────────────────────
//
// The same known-bad IOC is benign or malicious depending on WHERE it sits: a
// C2 IP wired into executed source/install hooks is critical, the identical
// string sitting in a dependency's URI-parser test fixture or spliced out of a
// minified bundle is a false positive. iocFileTier scores a hit by its file's
// context so detection is preserved (real, executed references still mint) while
// the dominant FP classes are demoted (kept low for audit) or suppressed.

// iocTier is the severity tier a file's context assigns to IOC hits found in it.
type iocTier int

const (
	tierKeep     iocTier = iota // executed content — hits stay ClassEvidence (critical)
	tierDemote                  // benign-leaning content — hits demote to ClassContext (low)
	tierSuppress                // never-executed artifact — no evidence is produced
)

// tierClass maps a tier to the Evidence.Class it stamps. tierKeep yields the
// zero value (""), which ToFinding treats as ClassEvidence, so kept hits stay
// JSON-clean and back-compatible.
func tierClass(t iocTier) detect.Class {
	if t == tierDemote {
		return detect.ClassContext
	}
	return ""
}

// iocFileTier classifies a file by its repo-relative path. Source maps are
// suppressed (generated debug data, never executed); test fixtures/files,
// example/demo trees and generated bundles are demoted to context; everything
// else (ordinary source, install hooks, binaries) is kept as evidence. Markdown
// is handled separately and earlier (isInertDoc, in scanFile).
func iocFileTier(relPath string) iocTier {
	p := "/" + strings.ToLower(strings.ReplaceAll(relPath, `\`, "/"))
	if strings.HasSuffix(p, ".map") {
		return tierSuppress
	}
	if isTestArtifact(p) || isExampleArtifact(p) || isGeneratedBundle(p) {
		return tierDemote
	}
	return tierKeep
}

// testPathSegments are directory names whose contents are a package's own test
// inputs, not code the consumer executes. fixtures hold literal sample data
// (URIs, payloads, hosts) that collides with known-bad IOC values.
var testPathSegments = []string{
	"/test/", "/tests/", "/__tests__/", "/__fixtures__/", "/fixtures/",
	"/spec/", "/__mocks__/",
}

// isTestArtifact reports whether p (lowercased, slash-normalised, leading-slash
// prefixed) is a test fixture directory or a test file.
func isTestArtifact(p string) bool {
	for _, seg := range testPathSegments {
		if strings.Contains(p, seg) {
			return true
		}
	}
	base := p[strings.LastIndexByte(p, '/')+1:]
	return strings.Contains(base, ".test.") ||
		strings.Contains(base, ".spec.") ||
		strings.HasSuffix(base, "_test.go") ||
		strings.HasSuffix(base, ".snap") ||
		base == "conftest.py"
}

// examplePathSegments are directories of runnable samples/demos shipped for
// documentation — illustrative endpoints, not the package's own runtime.
var examplePathSegments = []string{
	"/example/", "/examples/", "/sample/", "/samples/", "/demo/", "/demos/",
}

func isExampleArtifact(p string) bool {
	for _, seg := range examplePathSegments {
		if strings.Contains(p, seg) {
			return true
		}
	}
	return false
}

// minifiedBundleSuffixes are minified-bundle extensions whose dense generated
// content splices IOC values out of library data; isMinifiedLine catches
// un-suffixed bundles line-by-line.
var minifiedBundleSuffixes = []string{".min.js", ".min.mjs", ".min.cjs", ".min.css"}

// isGeneratedBundle reports whether p is generated/bundled output: a /dist/
// directory or a minified-bundle filename. Such files DO execute (so hits are
// demoted, not suppressed), but a bare IOC string in them is overwhelmingly
// bundled library data, not a live endpoint the bundle connects to.
func isGeneratedBundle(p string) bool {
	if strings.Contains(p, "/dist/") {
		return true
	}
	for _, suf := range minifiedBundleSuffixes {
		if strings.HasSuffix(p, suf) {
			return true
		}
	}
	return false
}

// isMinifiedLine reports whether a line looks machine-minified — very long with
// almost no whitespace. Such lines pack numeric data that collides with IP
// octets, so IPv4 matching is suppressed on them. The threshold is deliberately
// high so ordinary source/log lines (which carry real IP IOCs) are unaffected.
func isMinifiedLine(line string) bool {
	const minLen = 2000
	if len(line) < minLen {
		return false
	}
	ws := 0
	for i := 0; i < len(line); i++ {
		if c := line[i]; c == ' ' || c == '\t' {
			ws++
		}
	}
	return ws*50 < len(line) // < 2% whitespace
}

// urlHost returns the host of a URL, or "" if it cannot be parsed.
func urlHost(u string) string {
	parsed, err := url.Parse(u)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

// ── Content helpers (shared by the in-memory and filesystem paths) ───────────

type stringHit struct {
	value  string
	offset int64
}

// extractStrings returns every printable-ASCII run of at least minLen bytes,
// each with its starting byte offset. Mirrors the CLI binary scanner's
// extraction but keeps all runs (no relevance filter) so IOCs can be matched.
func extractStrings(data []byte, minLen int) []stringHit {
	var out []stringHit
	start := -1
	for i, b := range data {
		if b >= 0x20 && b <= 0x7e {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 && i-start >= minLen {
			out = append(out, stringHit{value: string(data[start:i]), offset: int64(start)})
		}
		start = -1
	}
	if start >= 0 && len(data)-start >= minLen {
		out = append(out, stringHit{value: string(data[start:]), offset: int64(start)})
	}
	return out
}

var elfMagic = []byte{0x7f, 'E', 'L', 'F'}

// isBinary classifies content as binary if it starts with the ELF magic or
// contains a NUL byte within the first binarySniffBytes.
func isBinary(data []byte) bool {
	if len(data) >= 4 && bytes.Equal(data[:4], elfMagic) {
		return true
	}
	n := min(len(data), binarySniffBytes)
	return bytes.IndexByte(data[:n], 0) >= 0
}

// splitLinesString splits s into lines on "\n", trimming a trailing "\r".
func splitLinesString(s string) []string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimSuffix(l, "\r")
	}
	return lines
}

func contextBefore(lines []string, i, n int) []string {
	start := max(i-n, 0)
	if start >= i {
		return nil
	}
	return append([]string(nil), lines[start:i]...)
}

func contextAfter(lines []string, i, n int) []string {
	end := min(i+1+n, len(lines))
	if i+1 >= end {
		return nil
	}
	return append([]string(nil), lines[i+1:end]...)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
