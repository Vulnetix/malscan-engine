package detect

import (
	"path"
	"regexp"
	"strings"
)

// The registry processors concatenate a package's files into PkgbuildContent, each preceded by
// a marker line naming it: `// ==== src/index.js ====`, `# ==== setup.py ====` or
// `<!-- ==== build/x.targets ==== -->`. fileIndex recovers that structure so a rule can be judged
// by the file it matched in.
//
// Measured in the 2026-10-25 audit of 18,715 malware mints (82% withdrawn as false positives):
// *_test.go and testdata/ alone were the basis of 230 of 641 Go still-malicious mints; the rest
// of the recurring classes were detector tables in tests, docs and examples, CI files, lockfile
// and go.sum dependency names, and one language's rule firing in another language's file
// (PHP-CREATE-FUNCTION on mlua's create_function, Python rules on Rust sources).
var fileMarkerRe = regexp.MustCompile(`^(?://|#|<!--)[ \t]*==== (.+?) ====[ \t]*(?:-->)?[ \t]*$`)

// fileSeg is one file's lines in the concatenated content: [start, end) line indexes, the marker
// line excluded.
type fileSeg struct {
	path       string
	start, end int
	marker     int // line index of the marker
}

// fileIndex is the per-file structure of one content string. Views of the same content that keep
// its line count (pythonLibraryViews' docView and execView do) share it.
type fileIndex struct {
	segs  []fileSeg
	lines int
	eco   string
	cache map[string]string
}

// newFileIndex returns nil when content carries no file markers: single-file content (a
// PKGBUILD, a setup.py on its own, a CLI scan of one file) is judged as a whole, as before.
func newFileIndex(content, eco string) *fileIndex {
	if !strings.Contains(content, "==== ") {
		return nil
	}
	lines := strings.Split(content, "\n")
	var segs []fileSeg
	for i, l := range lines {
		m := fileMarkerRe.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		if n := len(segs); n > 0 {
			segs[n-1].end = i
		}
		segs = append(segs, fileSeg{path: strings.TrimSpace(m[1]), start: i + 1, end: len(lines), marker: i})
	}
	if len(segs) == 0 {
		return nil
	}
	return &fileIndex{segs: segs, lines: len(lines), eco: strings.ToLower(strings.TrimSpace(eco)), cache: map[string]string{}}
}

// keep blanks every line of view (cached under its name: "content" or "exec") that is not in a file accepted by want, and every marker line.
// Text before the first marker (a processor's preamble, a gemspec) is kept: it is not a file the
// index can judge. The result has view's line count. A view whose line count differs from the
// indexed content is returned unchanged rather than mis-aligned.
func (fi *fileIndex) keep(view, name, key string, want func(p string) bool) string {
	ck := name + "\x00" + key
	if v, ok := fi.cache[ck]; ok {
		return v
	}
	lines := strings.Split(view, "\n")
	if len(lines) != fi.lines {
		return view
	}
	for _, s := range fi.segs {
		lines[s.marker] = ""
		if want(s.path) {
			continue
		}
		for i := s.start; i < s.end; i++ {
			lines[i] = ""
		}
	}
	out := strings.Join(lines, "\n")
	fi.cache[ck] = out
	return out
}

// view is view restricted to the files a rule may judge: those matching exts (all files when
// exts is empty), and, with surfaceOnly, not a test, doc, example, CI file, lockfile or unloaded
// vendored copy (see nonSurfacePath).
func (fi *fileIndex) view(view, name string, exts []string, surfaceOnly bool) string {
	key := strings.Join(exts, ",")
	if surfaceOnly {
		key += "\x00surface"
	}
	return fi.keep(view, name, key, func(p string) bool {
		return (len(exts) == 0 || pathMatches(p, exts)) && !(surfaceOnly && nonSurfacePath(p, fi.eco))
	})
}

// pathMatches reports whether a file path matches a file_exts entry: ".php" matches by extension,
// anything else ("go.mod", "Rakefile") matches the base name. Case-insensitive.
func pathMatches(p string, exts []string) bool {
	base := strings.ToLower(path.Base(strings.ReplaceAll(p, `\`, "/")))
	for _, e := range exts {
		e = strings.ToLower(e)
		if strings.HasPrefix(e, ".") {
			if strings.HasSuffix(base, e) {
				return true
			}
		} else if base == e {
			return true
		}
	}
	return false
}

var (
	// Directory segments whose files are not part of what the package runs.
	nonSurfaceDirs = map[string]bool{
		"test": true, "tests": true, "spec": true, "specs": true, "__tests__": true, "__mocks__": true,
		"testdata": true, "test_data": true, "fixtures": true, "testing": false,
		"doc": true, "docs": true, "example": true, "examples": true, "_examples": true,
		".github": true, ".circleci": true, ".gitlab": true, ".buildkite": true,
	}
	// Whole files that only declare or document: lockfiles and dependency lists, prose.
	nonSurfaceFiles = map[string]bool{
		"go.sum": true, "modules.txt": true, "composer.lock": true, "package-lock.json": true,
		"yarn.lock": true, "pnpm-lock.yaml": true, "cargo.lock": true, "poetry.lock": true,
		"pipfile.lock": true, "gemfile.lock": true, "pubspec.lock": true, "mix.lock": true,
		".gitlab-ci.yml": true, ".travis.yml": true, "appveyor.yml": true, "conftest.py": true,
	}
	nonSurfaceExts = []string{".md", ".markdown", ".rst", ".adoc", ".rdoc", ".textile"}
	testNameRe     = regexp.MustCompile(`(_test\.(go|rs|py|exs)|\.(test|spec)\.[cm]?[jt]sx?|_spec\.rb|^test_[^/]*\.py)$`)
)

// nonSurfacePath reports whether a file in a package's shipped sources never runs as part of the
// package: a test, a doc, an example, CI configuration, a lockfile, or a vendored copy that the
// ecosystem does not load. A match found only in such files is context, never evidence.
//
// node_modules/ is a surface on npm (bundledDependencies are loaded at runtime) and vendor/ is
// one on packagist (a shipped vendor/autoload.php may be required); elsewhere both are copies the
// consumer never loads (Go ignores a dependency's vendor/ in module mode).
func nonSurfacePath(p, eco string) bool {
	p = strings.ToLower(strings.ReplaceAll(p, `\`, "/"))
	base := path.Base(p)
	if nonSurfaceFiles[base] || testNameRe.MatchString(base) {
		return true
	}
	for _, e := range nonSurfaceExts {
		if strings.HasSuffix(base, e) {
			return true
		}
	}
	for _, seg := range strings.Split(path.Dir(p), "/") {
		switch {
		case nonSurfaceDirs[seg]:
			return true
		case seg == "node_modules" && eco != "npm":
			return true
		case seg == "vendor" && eco != "packagist":
			return true
		case seg == ".yarn":
			return true
		}
	}
	return false
}
