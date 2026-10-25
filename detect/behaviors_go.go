package detect

import (
	"regexp"
	"strings"
)

// GO-INIT-HTTP-EXEC: a Go package whose init() registers HTTP handlers on the default mux, in a
// file where request values reach exec.Command. Importing the package is enough: init() runs at
// import, the handlers go live on whatever server the importing program starts, and any client can
// then run commands. github.com/adrianicsro/testkusion v0.1.1 (GCVE-110-GO-2026-013108, confirmed
// in the 2026-10-25 audit) registers /exec (sh -c ?cmd), /reverse, /upload and /download this way.
// A library that serves commands on purpose does it from a constructor the caller invokes, never
// from init(); net/http/pprof registers from init() but executes nothing.
var (
	goInitOpenRe    = regexp.MustCompile(`(?m)^func init\(\)\s*\{`)
	goHandleRe      = regexp.MustCompile(`\bhttp\.(HandleFunc|Handle)\(`)
	goRequestValRe  = regexp.MustCompile(`\.(URL\.Query\(\)|FormValue\(|PostFormValue\(|Header\.Get\()`)
	goExecCommandRe = regexp.MustCompile(`\bexec\.Command(Context)?\(`)
)

// analyzeGoInitBackdoor applies GO-INIT-HTTP-EXEC to every Go file that runs (see fileIndex),
// or to unmarked content as one file.
func analyzeGoInitBackdoor(content string) []Finding {
	if !strings.Contains(content, "func init()") || !goExecCommandRe.MatchString(content) {
		return nil
	}
	var files []string
	if fi := newFileIndex(content, "go"); fi != nil {
		lines := strings.Split(content, "\n")
		for _, s := range fi.segs {
			if pathMatches(s.path, []string{".go"}) && !nonSurfacePath(s.path, "go") {
				files = append(files, strings.Join(lines[s.start:s.end], "\n"))
			}
		}
	} else {
		files = []string{content}
	}
	for _, src := range files {
		if !goExecCommandRe.MatchString(src) || !goRequestValRe.MatchString(src) {
			continue
		}
		for _, body := range goInitBodies(src) {
			if goHandleRe.MatchString(body) {
				f := qualifiedEvidence("GO-INIT-HTTP-EXEC", "behavioral",
					"Go init() registers HTTP handlers at import time in a file where request values reach exec.Command (import-time command backdoor)")
				f.MatchedLine = firstMatchingLine(body, goHandleRe)
				return []Finding{f}
			}
		}
	}
	return nil
}

// goInitBodies returns the body of every func init() in src, by brace matching. Braces inside
// string and rune literals are skipped; a body left unbalanced at end of file runs to the end.
func goInitBodies(src string) []string {
	var out []string
	for _, loc := range goInitOpenRe.FindAllStringIndex(src, -1) {
		depth, i := 1, loc[1]
		for ; i < len(src) && depth > 0; i++ {
			switch c := src[i]; c {
			case '{':
				depth++
			case '}':
				depth--
			case '"', '\'', '`':
				for i++; i < len(src) && src[i] != c; i++ {
					if src[i] == '\\' && c != '`' {
						i++
					}
				}
			}
		}
		out = append(out, src[loc[1]:min(i, len(src))])
	}
	return out
}
