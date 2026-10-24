package detect

import (
	"regexp"
	"strings"
)

// Python library views: what a pypi package's runtime source says, as opposed to what it does.
//
// A Python library carries a great deal of text the interpreter never runs as a command:
// docstrings, comments, and data — deny-lists, risk-score keyword lists, test vectors. Audited
// pypi disputes (2026-10) were all of this shape:
//
//	"""Install with:  !curl -fsSL https://… | sh"""          a docstring
//	risky_domains = ['pastebin', 'ngrok', 'transfer.sh', …]  a risk-score list
//	DENY = ["~/.aws/credentials", "~/.ssh/**"]               a hook's deny-list
//	CASES = ("nohup env", "echo $GITHUB_TOKEN", …)           test vectors
//
// pythonLibraryViews returns two views of the same text, each the same length with every
// newline in place, so line numbers and byte offsets survive:
//
//   - docView blanks docstrings (a non-f triple-quoted string that is a statement of its own)
//     and `#` comments. Nothing in them executes. Rules match against this view.
//   - execView additionally blanks every line that is wholly an element of a string-literal
//     list, tuple or set (with at most a `NAME =` prefix and trailing commas/closers). A rule
//     that matches docView but not execView is recorded, but as ClassContext.
//
// It is deliberately conservative:
//   - It is applied only to pypi library content (PkgbuildContent, PkgbuildExecutes=false),
//     never to the install surface, and within that only to `.py` members other than setup.py,
//     which executes at install time (members are split on the processor's `# ==== path ====`
//     separators; unlabelled content is read as Python).
//   - A segment that reads `__doc__` keeps its docstrings: exec(__doc__) is a known way to
//     hide a payload in one.
//   - f-strings are never blanked or treated as data: their {…} parts are evaluated.
//   - A literal is data only when it holds at least two strings and nothing but strings,
//     numbers, True/False/None and nested data literals; when it is assigned (`X = [...]`,
//     `X += [...]`, a keyword argument `k=(...)`), returned, or a membership test — never a
//     positional argument of a call; and when none of its strings is a shell or interpreter
//     argv token ("sh", "bash", "-c", "python", …): `CMD = ["bash", "-c", "…"]` is a command.
//   - override_gate rules that are not demoted for this ecosystem (reverse and bind shells)
//     are not affected by execView (see matchSectionView).

var pySegmentHeaderRE = regexp.MustCompile(`(?m)^# ==== (.+) ====[ \t]*\r?$`)

// pythonLibraryViews splits content into members and builds the two views (see above).
func pythonLibraryViews(content string) (docView, execView string) {
	hdrs := pySegmentHeaderRE.FindAllStringSubmatchIndex(content, -1)
	if len(hdrs) == 0 {
		return pythonSegmentViews(content)
	}
	var doc, exe strings.Builder
	doc.Grow(len(content))
	exe.Grow(len(content))
	emit := func(seg, path string) {
		if isPythonLibraryMember(path) {
			d, e := pythonSegmentViews(seg)
			doc.WriteString(d)
			exe.WriteString(e)
			return
		}
		doc.WriteString(seg)
		exe.WriteString(seg)
	}
	// Text before the first header has no name; read it as Python.
	emit(content[:hdrs[0][0]], "")
	for i, h := range hdrs {
		header := content[h[0]:h[1]]
		doc.WriteString(header)
		exe.WriteString(header)
		end := len(content)
		if i+1 < len(hdrs) {
			end = hdrs[i+1][0]
		}
		emit(content[h[1]:end], content[h[2]:h[3]])
	}
	return doc.String(), exe.String()
}

// isPythonLibraryMember reports whether a member (by its path) is Python source the views may
// rewrite. "" is unlabelled content. setup.py runs at install time and is never rewritten.
func isPythonLibraryMember(path string) bool {
	if path == "" {
		return true
	}
	p := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(path), "\\", "/"))
	base := p[strings.LastIndex(p, "/")+1:]
	return strings.HasSuffix(base, ".py") && base != "setup.py"
}

type pyTok struct {
	kind       byte // 'N' name, '0' number, 'S' string, 'O' op, 'L' logical newline
	text       string
	start, end int // byte range in the segment
	line, last int // first and last line (0-based)
	depth      int // bracket depth at the token
	fstr       bool
	triple     bool
}

// pythonSegmentViews builds both views for one Python member.
func pythonSegmentViews(s string) (string, string) {
	if s == "" {
		return s, s
	}
	toks, comments := pyLex(s)
	doc := []byte(s)
	for _, c := range comments {
		blankRange(doc, c[0], c[1])
	}
	if !strings.Contains(s, "__doc__") {
		for _, k := range pyDocstrings(toks) {
			blankRange(doc, toks[k].start, toks[k].end)
		}
	}
	lines := pyLiteralLines(toks)
	if len(lines) == 0 {
		d := string(doc)
		return d, d
	}
	exe := append([]byte(nil), doc...)
	line, lineStart := 0, 0
	for i := 0; i <= len(exe); i++ {
		if i == len(exe) || exe[i] == '\n' {
			if lines[line] {
				blankRange(exe, lineStart, i)
			}
			line++
			lineStart = i + 1
		}
	}
	return string(doc), string(exe)
}

// blankRange replaces every byte of b[from:to] except newlines with a space.
func blankRange(b []byte, from, to int) {
	for i := from; i < to && i < len(b); i++ {
		if b[i] != '\n' && b[i] != '\r' {
			b[i] = ' '
		}
	}
}

func isPyNameByte(c byte) bool {
	return c == '_' || c >= 0x80 || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func isPyStringPrefix(p string) bool {
	switch strings.ToLower(p) {
	case "r", "u", "b", "f", "br", "rb", "fr", "rf":
		return true
	}
	return false
}

// pyLex tokenizes a Python member far enough to find strings, comments, brackets and
// statement boundaries. It returns the tokens and the [start,end) byte ranges of comments.
func pyLex(s string) ([]pyTok, [][2]int) {
	var toks []pyTok
	var comments [][2]int
	line, depth := 0, 0
	emit := func(t pyTok) {
		t.depth = depth
		toks = append(toks, t)
	}
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == '\n':
			if depth == 0 {
				emit(pyTok{kind: 'L', start: i, end: i + 1, line: line, last: line})
			}
			line++
			i++
		case c == '\\' && i+1 < len(s) && (s[i+1] == '\n' || (s[i+1] == '\r' && i+2 < len(s) && s[i+2] == '\n')):
			// Explicit line continuation: no logical newline.
			if s[i+1] == '\r' {
				i++
			}
			line++
			i += 2
		case c == ' ' || c == '\t' || c == '\r' || c == '\f':
			i++
		case c == '#':
			j := strings.IndexByte(s[i:], '\n')
			if j < 0 {
				j = len(s) - i
			}
			comments = append(comments, [2]int{i, i + j})
			i += j
		case c == '"' || c == '\'':
			t := pyLexString(s, i, "", &line)
			emit(t)
			i = t.end
		case isPyNameByte(c) && !(c >= '0' && c <= '9'):
			j := i
			for j < len(s) && isPyNameByte(s[j]) {
				j++
			}
			if j < len(s) && (s[j] == '"' || s[j] == '\'') && isPyStringPrefix(s[i:j]) {
				t := pyLexString(s, j, s[i:j], &line)
				t.start = i
				emit(t)
				i = t.end
				continue
			}
			emit(pyTok{kind: 'N', text: s[i:j], start: i, end: j, line: line, last: line})
			i = j
		case c >= '0' && c <= '9' || (c == '.' && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9'):
			j := i + 1
			for j < len(s) && (isPyNameByte(s[j]) || s[j] == '.') {
				j++
			}
			emit(pyTok{kind: '0', text: s[i:j], start: i, end: j, line: line, last: line})
			i = j
		default:
			n := 1
			if strings.HasPrefix(s[i:], "...") {
				n = 3
			} else if i+1 < len(s) {
				two := s[i : i+2]
				if two == "->" || two == "**" || two == "//" || two == "<<" || two == ">>" ||
					(s[i+1] == '=' && strings.IndexByte("=!<>:+-*/%&|^@", c) >= 0) {
					n = 2
				}
			}
			op := s[i : i+n]
			switch op {
			case "(", "[", "{":
				emit(pyTok{kind: 'O', text: op, start: i, end: i + n, line: line, last: line})
				depth++
			case ")", "]", "}":
				if depth > 0 {
					depth--
				}
				emit(pyTok{kind: 'O', text: op, start: i, end: i + n, line: line, last: line})
			default:
				emit(pyTok{kind: 'O', text: op, start: i, end: i + n, line: line, last: line})
			}
			i += n
		}
	}
	return toks, comments
}

// pyLexString scans the string literal whose opening quote is at s[q]. line is advanced past
// any newlines inside a triple-quoted string.
func pyLexString(s string, q int, prefix string, line *int) pyTok {
	quote := s[q]
	t := pyTok{kind: 'S', start: q, line: *line, fstr: strings.ContainsAny(prefix, "fF")}
	i := q + 1
	if strings.HasPrefix(s[q:], strings.Repeat(string(quote), 3)) {
		t.triple = true
		i = q + 3
		closer := strings.Repeat(string(quote), 3)
		for i < len(s) {
			if s[i] == '\\' && i+1 < len(s) {
				if s[i+1] == '\n' {
					*line++
				}
				i += 2
				continue
			}
			if s[i] == '\n' {
				*line++
			}
			if strings.HasPrefix(s[i:], closer) {
				i += 3
				break
			}
			i++
		}
	} else {
		for i < len(s) {
			if s[i] == '\\' && i+1 < len(s) && s[i+1] != '\n' {
				i += 2
				continue
			}
			if s[i] == '\n' {
				break // unterminated: end at the line
			}
			if s[i] == quote {
				i++
				break
			}
			i++
		}
	}
	if i > len(s) {
		i = len(s)
	}
	t.end = i
	t.last = *line
	t.text = s[q:i]
	return t
}

// pyDocstrings returns the indexes of string tokens that are docstrings: a non-f triple-quoted
// string that is a whole statement (at the start of a logical line, or right after the colon of
// a def/class header) and is followed by the end of that statement.
func pyDocstrings(toks []pyTok) []int {
	var out []int
	stmtStart := 0 // index of the first token of the current logical line
	for k, t := range toks {
		if t.kind == 'L' || (t.kind == 'O' && t.text == ";" && t.depth == 0) {
			stmtStart = k + 1
			continue
		}
		if t.kind != 'S' || !t.triple || t.fstr || t.depth != 0 {
			continue
		}
		atStart := k == stmtStart
		if !atStart && k > 0 && toks[k-1].kind == 'O' && toks[k-1].text == ":" && toks[k-1].depth == 0 {
			// `def f(): """doc"""` / `class C: """doc"""`.
			if first := toks[stmtStart]; first.kind == 'N' && (first.text == "def" || first.text == "class" || first.text == "async") {
				atStart = true
			}
		}
		if !atStart {
			continue
		}
		if k+1 < len(toks) {
			if n := toks[k+1]; !(n.kind == 'L' || (n.kind == 'O' && n.text == ";")) {
				continue
			}
		}
		out = append(out, k)
	}
	return out
}

// pyArgvTokens are strings that make a list an argv rather than data.
var pyArgvTokens = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "fish": true,
	"/bin/sh": true, "/bin/bash": true, "/usr/bin/sh": true, "/usr/bin/bash": true, "/usr/bin/env": true, "env": true,
	"-c": true, "/c": true, "-e": true, "cmd": true, "cmd.exe": true, "powershell": true, "powershell.exe": true, "pwsh": true,
	"python": true, "python3": true, "node": true, "perl": true, "ruby": true, "php": true, "nohup": true, "sudo": true,
}

// pyStringValue strips a string token's prefix and quotes.
func pyStringValue(t pyTok) string {
	s := t.text
	n := 1
	if t.triple {
		n = 3
	}
	if len(s) >= 2*n {
		return s[n : len(s)-n]
	}
	return ""
}

var pyLiteralKeywordsBefore = map[string]bool{
	"in": true, "not": true, "and": true, "or": true, "return": true, "yield": true,
	"else": true, "if": true, "elif": true, "assert": true, "is": true, "while": true,
}

type pyFrame struct {
	open      int  // token index of the opener
	literal   bool // the opener starts a display (list/tuple/set/dict), not a call or subscript
	pure      bool // holds only non-f strings, numbers, True/False/None, commas, colons and pure nested displays
	nstr      int
	comma     bool
	argv      bool
	dataCtx   bool // assigned, returned, a keyword value, or nested in a data display
	parentLit bool
}

// pyLiteralLines reports, per physical line, whether the line is wholly an element of a
// data literal (see pythonLibraryViews).
func pyLiteralLines(toks []pyTok) map[int]bool {
	covered := make([]bool, len(toks))
	var stack []*pyFrame
	for k, t := range toks {
		if len(stack) > 0 {
			top := stack[len(stack)-1]
			switch {
			case t.kind == 'S':
				if t.fstr {
					top.pure = false
				} else {
					top.nstr++
					if pyArgvTokens[strings.ToLower(strings.TrimSpace(pyStringValue(t)))] {
						top.argv = true
					}
				}
			case t.kind == '0':
			case t.kind == 'N':
				if t.text != "True" && t.text != "False" && t.text != "None" {
					top.pure = false
				}
			case t.kind == 'O':
				switch t.text {
				case ",":
					top.comma = true
				case ":", "...", "-", "(", "[", "{", ")", "]", "}":
				default:
					top.pure = false
				}
			}
		}
		if t.kind != 'O' {
			continue
		}
		switch t.text {
		case "(", "[", "{":
			f := &pyFrame{open: k, pure: true}
			var prev *pyTok
			if k > 0 {
				prev = &toks[k-1]
			}
			switch {
			case prev == nil:
				f.literal = true
			case prev.kind == 'N':
				f.literal = pyLiteralKeywordsBefore[prev.text] || prev.text == "return"
			case prev.kind == 'S' || prev.kind == '0':
				f.literal = false
			case prev.kind == 'O' && (prev.text == ")" || prev.text == "]" || prev.text == "}"):
				f.literal = false
			default:
				f.literal = true
			}
			var parent *pyFrame
			if len(stack) > 0 {
				parent = stack[len(stack)-1]
			}
			f.parentLit = parent != nil && parent.literal
			switch {
			case prev != nil && prev.kind == 'O' && (prev.text == "=" || prev.text == "+=" || prev.text == "|="):
				f.dataCtx = true
			case prev != nil && prev.kind == 'N' && (prev.text == "return" || prev.text == "in"):
				f.dataCtx = true
			case parent != nil && parent.literal:
				f.dataCtx = true // nested: the parent decides
			case parent == nil && (prev == nil || prev.kind == 'L'):
				f.dataCtx = true // a bare display statement
			}
			stack = append(stack, f)
		case ")", "]", "}":
			if len(stack) == 0 {
				continue
			}
			f := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			ok := f.literal && f.pure && !f.argv && f.nstr > 0
			if ok && toks[f.open].text == "(" && !f.comma {
				ok = false // `("x")` is grouping, not a tuple
			}
			if len(stack) > 0 {
				parent := stack[len(stack)-1]
				if !ok {
					parent.pure = false
				} else {
					parent.nstr += f.nstr
					parent.argv = parent.argv || f.argv
				}
			}
			// A collection: at least two strings. `WEBHOOK = ["https://…"]` is one value in
			// brackets, not a list of things a package screens for.
			if ok && f.dataCtx && !f.parentLit && f.nstr >= 2 {
				for i := f.open; i <= k; i++ {
					covered[i] = true
				}
			}
		}
	}

	// A line is a literal line when its tokens are: an optional `NAME(.NAME)* [: ann] (=|+=)`
	// or `return` prefix, then covered tokens, then only commas and closers.
	byLine := map[int][]int{}
	for k, t := range toks {
		if t.kind == 'L' {
			continue
		}
		byLine[t.line] = append(byLine[t.line], k)
	}
	out := map[int]bool{}
	for ln, ks := range byLine {
		first := -1
		for j, k := range ks {
			if covered[k] {
				first = j
				break
			}
		}
		if first < 0 || !pyAllowedPrefix(toks, ks[:first]) {
			continue
		}
		ok := true
		seenUncovered := false
		for _, k := range ks[first:] {
			if covered[k] && !seenUncovered {
				continue
			}
			seenUncovered = true
			if t := toks[k]; !(t.kind == 'O' && (t.text == "," || t.text == ")" || t.text == "]" || t.text == "}")) {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		out[ln] = true
		// Continuation lines of a multi-line string element belong to the element.
		for _, k := range ks {
			if covered[k] {
				for l := toks[k].line + 1; l <= toks[k].last; l++ {
					out[l] = true
				}
			}
		}
	}
	// Lines inside a covered multi-line string that start no token of their own.
	for k, t := range toks {
		if covered[k] && t.last > t.line && out[t.line] {
			for l := t.line + 1; l <= t.last; l++ {
				out[l] = true
			}
		}
	}
	return out
}

// pyAllowedPrefix reports whether the tokens before a data literal on its line are an
// assignment target (`NAME`, `a.b`, `NAME: ann`, followed by `=`, `+=` or `|=`) or `return`.
func pyAllowedPrefix(toks []pyTok, ks []int) bool {
	if len(ks) == 0 {
		return true
	}
	if len(ks) == 1 && toks[ks[0]].kind == 'N' && toks[ks[0]].text == "return" {
		return true
	}
	if toks[ks[0]].kind != 'N' {
		return false
	}
	last := toks[ks[len(ks)-1]]
	if last.kind != 'O' || (last.text != "=" && last.text != "+=" && last.text != "|=") {
		return false
	}
	for _, k := range ks[1 : len(ks)-1] {
		t := toks[k]
		switch {
		case t.kind == 'N':
		case t.kind == 'O' && (t.text == "." || t.text == ":" || t.text == "[" || t.text == "]" || t.text == ","):
		default:
			return false // a call, an operator: not a plain assignment target
		}
	}
	return true
}
