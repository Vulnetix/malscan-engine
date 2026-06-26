package iocscan

import (
	"bytes"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Defaults for a Scan.
const (
	DefaultContextLines = 3
	DefaultMaxFileSize  = 10 << 20 // 10 MiB
	stringMinLen        = 6        // shortest printable run extracted from a binary
	binarySniffBytes    = 8192     // bytes inspected for NUL when classifying a file
)

// defaultSkipDirs are directory names pruned from the walk by default. A caller
// can override the whole set via Options.SkipDirs (a non-nil empty slice scans
// everything).
var defaultSkipDirs = []string{".git", ".hg", ".svn", "node_modules", "vendor", ".vulnetix"}

// Options configure a Scan. The zero value (with a Root) is valid: feeds load
// from the public index into the OS temp cache and every file under Root is
// scanned for known-bad domain/IP/URL indicators.
type Options struct {
	Root         string   // working directory to scan (default ".")
	Ecosystem    string   // registry slug; the "generic" feed is always included too
	Depth        int      // max directory depth to descend; <= 0 means unlimited
	IncludeExt   []string // if non-empty, only these file extensions are scanned
	ExcludeExt   []string // these file extensions are skipped (takes precedence)
	ContextLines int      // lines of context above & below a hit (default 3)

	// BinaryAnalysis, when true, also extracts printable strings from binary
	// files (ELF and any NUL-containing file) and matches IOCs in them. This is
	// the in-engine equivalent of hooking a binary malscan, but hunting domain/IP
	// indicators instead of secrets.
	BinaryAnalysis bool

	MaxFileSize int64    // skip files larger than this (default 10 MiB)
	SkipDirs    []string // directory names to prune; nil = defaultSkipDirs

	// Feed controls (all optional). Loader, when set, is used as-is and the rest
	// are ignored — the usual path for tests and for callers that share one
	// loader across scans.
	IndexURL   string
	CacheDir   string
	TTL        time.Duration
	HTTPClient *http.Client
	Loader     *FeedLoader

	now func() time.Time // test seam for the clock
}

// Scan loads the STIX feeds for opts.Ecosystem (plus "generic"), walks opts.Root
// honouring the depth and include/exclude-extension filters, and returns evidence
// for every file that references a known-bad indicator. An error is returned only
// when the feeds cannot be loaded at all (see FeedLoader.Load); the Report is
// still returned (with host info + any warnings) in that case.
func Scan(opts Options) (*Report, error) {
	now := time.Now
	if opts.now != nil {
		now = opts.now
	}

	root := opts.Root
	if root == "" {
		root = "."
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		absRoot = root
	}

	loader := opts.Loader
	if loader == nil {
		loader = &FeedLoader{
			IndexURL:   opts.IndexURL,
			CacheDir:   opts.CacheDir,
			TTL:        opts.TTL,
			HTTPClient: opts.HTTPClient,
			now:        opts.now,
		}
	}

	set, warnings, lerr := loader.Load(opts.Ecosystem)
	report := &Report{
		Host:      hostInfo(now()),
		Root:      absRoot,
		Ecosystem: opts.Ecosystem,
		Warnings:  warnings,
	}
	if lerr != nil {
		return report, lerr
	}
	report.IndicatorCount = set.Len()

	sc := newScanner(set, absRoot, opts)
	walkErr := filepath.WalkDir(absRoot, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("walk %s: %v", path, werr))
			return nil
		}
		if d.IsDir() {
			if path == absRoot {
				return nil
			}
			if sc.skipDir(d.Name()) {
				return filepath.SkipDir
			}
			if sc.maxDepth > 0 && dirDepth(absRoot, path) >= sc.maxDepth {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if !sc.extAllowed(path) {
			return nil
		}
		if info, ierr := d.Info(); ierr == nil && sc.maxSize > 0 && info.Size() > sc.maxSize {
			return nil
		}

		ev, scanned, serr := sc.scanFile(path)
		if serr != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("%s: %v", path, serr))
			return nil
		}
		if scanned {
			report.FilesScanned++
		}
		report.Evidence = append(report.Evidence, ev...)
		return nil
	})
	if walkErr != nil {
		report.Errors = append(report.Errors, fmt.Sprintf("walk root: %v", walkErr))
	}

	return report, nil
}

// scanner holds the resolved per-scan settings.
type scanner struct {
	set          *IndicatorSet
	root         string
	maxDepth     int
	contextLines int
	maxSize      int64
	binary       bool
	includeExt   map[string]bool
	excludeExt   map[string]bool
	skipDirs     map[string]bool
}

func newScanner(set *IndicatorSet, root string, opts Options) *scanner {
	ctxLines := opts.ContextLines
	if ctxLines <= 0 {
		ctxLines = DefaultContextLines
	}
	maxSize := opts.MaxFileSize
	if maxSize <= 0 {
		maxSize = DefaultMaxFileSize
	}
	skip := opts.SkipDirs
	if skip == nil {
		skip = defaultSkipDirs
	}
	return &scanner{
		set:          set,
		root:         root,
		maxDepth:     opts.Depth,
		contextLines: ctxLines,
		maxSize:      maxSize,
		binary:       opts.BinaryAnalysis,
		includeExt:   extSet(opts.IncludeExt),
		excludeExt:   extSet(opts.ExcludeExt),
		skipDirs:     nameSet(skip),
	}
}

func (sc *scanner) skipDir(name string) bool { return sc.skipDirs[name] }

// extAllowed reports whether a file's extension passes the include/exclude
// filters. Exclude takes precedence; a non-empty include list is an allowlist.
func (sc *scanner) extAllowed(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	if sc.excludeExt[ext] {
		return false
	}
	if len(sc.includeExt) > 0 {
		return sc.includeExt[ext]
	}
	return true
}

// scanFile reads a file and dispatches to the text or binary matcher. The
// boolean reports whether the file was actually scanned (a binary skipped
// because BinaryAnalysis is off counts as not-scanned).
func (sc *scanner) scanFile(path string) ([]Evidence, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}
	if len(data) == 0 {
		return nil, true, nil
	}
	if isBinary(data) {
		if !sc.binary {
			return nil, false, nil
		}
		return sc.scanBinary(path, data), true, nil
	}
	return sc.scanText(path, data), true, nil
}

// scanText splits a file into lines and matches each, attaching context lines.
func (sc *scanner) scanText(path string, data []byte) []Evidence {
	lines := splitLines(data)
	rel := sc.rel(path)
	var ev []Evidence
	for i, line := range lines {
		for _, m := range sc.matchLine(line) {
			ev = append(ev, Evidence{
				IndicatorType:  m.typ,
				IndicatorValue: m.value,
				Indicator:      m.ind,
				FilePath:       path,
				RelPath:        rel,
				LineNumber:     i + 1,
				ColStart:       m.col,
				ColEnd:         m.col + len(m.value),
				MatchedLine:    line,
				ContextBefore:  contextBefore(lines, i, sc.contextLines),
				ContextAfter:   contextAfter(lines, i, sc.contextLines),
			})
		}
	}
	return ev
}

// scanBinary extracts printable strings from a binary and matches IOCs in them,
// deduplicating across the whole file.
func (sc *scanner) scanBinary(path string, data []byte) []Evidence {
	rel := sc.rel(path)
	seen := map[string]bool{}
	var ev []Evidence
	for _, sh := range extractStrings(data, stringMinLen) {
		for _, m := range sc.matchLine(sh.value) {
			key := string(m.typ) + "|" + strings.ToLower(m.value)
			if seen[key] {
				continue
			}
			seen[key] = true
			ev = append(ev, Evidence{
				IndicatorType:  m.typ,
				IndicatorValue: m.value,
				Indicator:      m.ind,
				FilePath:       path,
				RelPath:        rel,
				IsBinary:       true,
				ByteOffset:     sh.offset + int64(m.col),
				MatchedLine:    truncate(sh.value, 200),
			})
		}
	}
	return ev
}

func (sc *scanner) rel(path string) string {
	if r, err := filepath.Rel(sc.root, path); err == nil {
		return r
	}
	return path
}

// ── Matching ──────────────────────────────────────────────────────────────

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
// (type, value). It is also used line-equivalently over strings extracted from
// binaries.
func (sc *scanner) matchLine(s string) []lineMatch {
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
		if ind := sc.set.LookupURL(u); ind != nil {
			add(TypeURL, u, loc[0], ind)
		}
		if host := urlHost(u); host != "" {
			if ind := sc.set.LookupDomain(host); ind != nil {
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
		if ind := sc.set.LookupDomain(dom); ind != nil {
			add(TypeDomain, dom, loc[0], ind)
		}
	}

	// IPv4.
	for _, loc := range ipv4Re.FindAllStringIndex(s, -1) {
		ipStr := s[loc[0]:loc[1]]
		if ip := net.ParseIP(ipStr); ip != nil && ip.To4() != nil {
			if ind := sc.set.LookupIP(ipStr); ind != nil {
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
			if ind := sc.set.LookupIP(ipStr); ind != nil {
				add(TypeIPv6, ipStr, loc[0], ind)
			}
		}
	}

	return matches
}

// urlHost returns the host of a URL, or "" if it cannot be parsed.
func urlHost(u string) string {
	parsed, err := url.Parse(u)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

// ── File helpers ────────────────────────────────────────────────────────────

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

// isBinary classifies a file as binary if it starts with the ELF magic or
// contains a NUL byte within the first binarySniffBytes.
func isBinary(data []byte) bool {
	if len(data) >= 4 && bytes.Equal(data[:4], elfMagic) {
		return true
	}
	n := min(len(data), binarySniffBytes)
	return bytes.IndexByte(data[:n], 0) >= 0
}

// splitLines splits data into lines on "\n", trimming a trailing "\r".
func splitLines(data []byte) []string {
	lines := strings.Split(string(data), "\n")
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

// dirDepth returns the depth of dir below root: root itself is 0, an immediate
// subdirectory is 1, and so on.
func dirDepth(root, dir string) int {
	rel, err := filepath.Rel(root, dir)
	if err != nil || rel == "." {
		return 0
	}
	return strings.Count(rel, string(filepath.Separator)) + 1
}

// extSet normalises a list of extensions into a lookup set: lowercased, each
// with a leading dot.
func extSet(exts []string) map[string]bool {
	if len(exts) == 0 {
		return nil
	}
	out := make(map[string]bool, len(exts))
	for _, e := range exts {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" {
			continue
		}
		if !strings.HasPrefix(e, ".") {
			e = "." + e
		}
		out[e] = true
	}
	return out
}

func nameSet(names []string) map[string]bool {
	out := make(map[string]bool, len(names))
	for _, n := range names {
		if n != "" {
			out[n] = true
		}
	}
	return out
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
