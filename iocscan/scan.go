package iocscan

import (
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
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

	// Set, when non-nil, is the preloaded indicator set to scan against — the
	// feed is NOT loaded and the feed controls below are ignored. Use this to
	// reuse one IndicatorSet (and its parsed feeds) across many scans.
	Set *IndicatorSet

	// Feed controls (all optional, ignored when Set is non-nil). Loader, when
	// set, is used as-is and the rest are ignored.
	IndexURL   string
	CacheDir   string
	TTL        time.Duration
	HTTPClient *http.Client
	Loader     *FeedLoader

	now func() time.Time // test seam for the clock
}

// Scan loads the STIX feeds for opts.Ecosystem (plus "generic") — or uses
// opts.Set when provided — walks opts.Root honouring the depth and
// include/exclude-extension filters, and returns evidence for every file that
// references a known-bad indicator. An error is returned only when the feeds
// cannot be loaded at all (see FeedLoader.Load); the Report is still returned
// (with host info + any warnings) in that case.
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

	report := &Report{
		Host:      hostInfo(now()),
		Root:      absRoot,
		Ecosystem: opts.Ecosystem,
	}

	set := opts.Set
	if set == nil {
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
		loaded, warnings, lerr := loader.Load(opts.Ecosystem)
		report.Warnings = warnings
		if lerr != nil {
			return report, lerr
		}
		set = loaded
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

// scanner holds the resolved per-scan settings and the shared Matcher.
type scanner struct {
	matcher    *Matcher
	root       string
	maxDepth   int
	maxSize    int64
	binary     bool
	includeExt map[string]bool
	excludeExt map[string]bool
	skipDirs   map[string]bool
}

func newScanner(set *IndicatorSet, root string, opts Options) *scanner {
	maxSize := opts.MaxFileSize
	if maxSize <= 0 {
		maxSize = DefaultMaxFileSize
	}
	skip := opts.SkipDirs
	if skip == nil {
		skip = defaultSkipDirs
	}
	return &scanner{
		matcher:    NewMatcher(set, opts.ContextLines),
		root:       root,
		maxDepth:   opts.Depth,
		maxSize:    maxSize,
		binary:     opts.BinaryAnalysis,
		includeExt: extSet(opts.IncludeExt),
		excludeExt: extSet(opts.ExcludeExt),
		skipDirs:   nameSet(skip),
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
// because BinaryAnalysis is off counts as not-scanned). Evidence records the
// absolute path plus the repo-relative path.
func (sc *scanner) scanFile(path string) ([]Evidence, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}
	if len(data) == 0 {
		return nil, true, nil
	}
	rel := sc.rel(path)
	if isBinary(data) {
		if !sc.binary {
			return nil, false, nil
		}
		return sc.matcher.matchBinary(path, rel, data), true, nil
	}
	return sc.matcher.matchText(path, rel, string(data)), true, nil
}

func (sc *scanner) rel(path string) string {
	if r, err := filepath.Rel(sc.root, path); err == nil {
		return r
	}
	return path
}

// ── Walk helpers ─────────────────────────────────────────────────────────────

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
