package detect

import "testing"

// pylexWant is the expected shape of one token; every listed field is checked.
type pylexWant struct {
	kind       byte
	text       string
	start, end int
	line, last int
	depth      int
}

func checkPylex(t *testing.T, src string, want []pylexWant, wantComments [][2]int) {
	t.Helper()
	toks, comments := pyLex(src)
	if len(toks) != len(want) {
		t.Fatalf("pyLex(%q) = %d tokens, want %d:\n%+v", src, len(toks), len(want), toks)
	}
	for i, w := range want {
		g := toks[i]
		if g.kind != w.kind || g.text != w.text || g.start != w.start || g.end != w.end ||
			g.line != w.line || g.last != w.last || g.depth != w.depth {
			t.Errorf("pyLex(%q) token %d = {kind:%c text:%q start:%d end:%d line:%d last:%d depth:%d}, want {kind:%c text:%q start:%d end:%d line:%d last:%d depth:%d}",
				src, i, g.kind, g.text, g.start, g.end, g.line, g.last, g.depth,
				w.kind, w.text, w.start, w.end, w.line, w.last, w.depth)
		}
	}
	if len(comments) != len(wantComments) {
		t.Fatalf("pyLex(%q) = %d comment ranges %v, want %d", src, len(comments), comments, len(wantComments))
	}
	for i, c := range wantComments {
		if comments[i] != c {
			t.Errorf("pyLex(%q) comment %d = %v, want %v", src, i, comments[i], c)
		}
	}
}

func TestPyLexNewlinesAndBracketDepth(t *testing.T) {
	// A depth-0 newline is a logical-newline token carrying the line it ends (before the
	// increment); inside brackets it only counts lines, so the next token moves to it.
	checkPylex(t, "(\n", []pylexWant{{kind: 'O', text: "(", start: 0, end: 1, line: 0, last: 0, depth: 0}}, nil)
	checkPylex(t, "x = 1\n", []pylexWant{
		{kind: 'N', text: "x", start: 0, end: 1, line: 0, last: 0},
		{kind: 'O', text: "=", start: 2, end: 3, line: 0, last: 0},
		{kind: '0', text: "1", start: 4, end: 5, line: 0, last: 0},
		{kind: 'L', start: 5, end: 6, line: 0, last: 0},
	}, nil)
	checkPylex(t, "f(\n1,\n2)\n", []pylexWant{
		{kind: 'N', text: "f", start: 0, end: 1, line: 0, last: 0},
		{kind: 'O', text: "(", start: 1, end: 2, line: 0, last: 0},
		{kind: '0', text: "1", start: 3, end: 4, line: 1, last: 1, depth: 1},
		{kind: 'O', text: ",", start: 4, end: 5, line: 1, last: 1, depth: 1},
		{kind: '0', text: "2", start: 6, end: 7, line: 2, last: 2, depth: 1},
		{kind: 'O', text: ")", start: 7, end: 8, line: 2, last: 2, depth: 0},
		{kind: 'L', start: 8, end: 9, line: 2, last: 2},
	}, nil)
}

func TestPyLexLineContinuations(t *testing.T) {
	// Backslash + LF: no logical newline, the line counter advances.
	checkPylex(t, "x = 1 + \\\n2\n", []pylexWant{
		{kind: 'N', text: "x", start: 0, end: 1, line: 0, last: 0},
		{kind: 'O', text: "=", start: 2, end: 3, line: 0, last: 0},
		{kind: '0', text: "1", start: 4, end: 5, line: 0, last: 0},
		{kind: 'O', text: "+", start: 6, end: 7, line: 0, last: 0},
		{kind: '0', text: "2", start: 10, end: 11, line: 1, last: 1},
		{kind: 'L', start: 11, end: 12, line: 1, last: 1},
	}, nil)
	// Backslash + CRLF is consumed as one continuation.
	checkPylex(t, "x = \\\r\n2\n", []pylexWant{
		{kind: 'N', text: "x", start: 0, end: 1, line: 0, last: 0},
		{kind: 'O', text: "=", start: 2, end: 3, line: 0, last: 0},
		{kind: '0', text: "2", start: 7, end: 8, line: 1, last: 1},
		{kind: 'L', start: 8, end: 9, line: 1, last: 1},
	}, nil)
}

func TestPyLexWhitespaceAndComments(t *testing.T) {
	// Space, tab and formfeed are skipped without tokens.
	checkPylex(t, "a\t \fb", []pylexWant{
		{kind: 'N', text: "a", start: 0, end: 1, line: 0, last: 0},
		{kind: 'N', text: "b", start: 4, end: 5, line: 0, last: 0},
	}, nil)
	// A comment runs to the newline (exclusive); the newline still ends the statement.
	checkPylex(t, "a  # note\nb", []pylexWant{
		{kind: 'N', text: "a", start: 0, end: 1, line: 0, last: 0},
		{kind: 'L', start: 9, end: 10, line: 0, last: 0},
		{kind: 'N', text: "b", start: 10, end: 11, line: 1, last: 1},
	}, [][2]int{{3, 9}})
	// A comment on the last line with no newline after it ends at end of input.
	checkPylex(t, "x = 1  # trailing", []pylexWant{
		{kind: 'N', text: "x", start: 0, end: 1, line: 0, last: 0},
		{kind: 'O', text: "=", start: 2, end: 3, line: 0, last: 0},
		{kind: '0', text: "1", start: 4, end: 5, line: 0, last: 0},
	}, [][2]int{{7, 17}})
}

func TestPyLexStrings(t *testing.T) {
	// A plain single-quoted string: kind 'S'. The text runs from the opening quote to the
	// closing one; a prefix is reported through the token's start, not its text.
	checkPylex(t, "s = 'x'", []pylexWant{
		{kind: 'N', text: "s", start: 0, end: 1, line: 0, last: 0},
		{kind: 'O', text: "=", start: 2, end: 3, line: 0, last: 0},
		{kind: 'S', text: "'x'", start: 4, end: 7, line: 0, last: 0},
	}, nil)
	// A raw string keeps its backslash: the escape is not consumed.
	checkPylex(t, `a = r"\"`, []pylexWant{
		{kind: 'N', text: "a", start: 0, end: 1, line: 0, last: 0},
		{kind: 'O', text: "=", start: 2, end: 3, line: 0, last: 0},
		{kind: 'S', text: `"\"`, start: 4, end: 8, line: 0, last: 0},
	}, nil)
	checkPylex(t, `u"é"`, []pylexWant{{kind: 'S', text: `"é"`, start: 0, end: 5, line: 0, last: 0}}, nil)
	checkPylex(t, `b"payload"`, []pylexWant{{kind: 'S', text: `"payload"`, start: 0, end: 10, line: 0, last: 0}}, nil)
	checkPylex(t, `f"{x}"`, []pylexWant{{kind: 'S', text: `"{x}"`, start: 0, end: 6, line: 0, last: 0}}, nil)
	// Unterminated at end of input: the string ends at the last byte.
	checkPylex(t, `"abc`, []pylexWant{{kind: 'S', text: `"abc`, start: 0, end: 4, line: 0, last: 0}}, nil)
	// A single-quoted string cannot span a newline: it ends there, unterminated, and the
	// rest of the line is scanned normally (b"y" then reads as a b-prefixed string).
	checkPylex(t, "\"a\nb\"\n", []pylexWant{
		{kind: 'S', text: `"a`, start: 0, end: 2, line: 0, last: 0},
		{kind: 'L', start: 2, end: 3, line: 0, last: 0},
		{kind: 'S', text: `"`, start: 3, end: 5, line: 1, last: 1},
		{kind: 'L', start: 5, end: 6, line: 1, last: 1},
	}, nil)
	// A triple-quoted string spans lines: the token carries the last line it ends on.
	checkPylex(t, "\"\"\"doc\n\"\"\"\nx", []pylexWant{
		{kind: 'S', text: "\"\"\"doc\n\"\"\"", start: 0, end: 10, line: 0, last: 1},
		{kind: 'L', start: 10, end: 11, line: 1, last: 1},
		{kind: 'N', text: "x", start: 11, end: 12, line: 2, last: 2},
	}, nil)
}

func TestPyLexStringPrefixBoundaries(t *testing.T) {
	// The two-letter forms combine into one prefixed string too.
	checkPylex(t, `rb"\x00"`, []pylexWant{{kind: 'S', text: `"\x00"`, start: 0, end: 8, line: 0, last: 0}}, nil)
	checkPylex(t, `fr"{x}"`, []pylexWant{{kind: 'S', text: `"{x}"`, start: 0, end: 7, line: 0, last: 0}}, nil)
	checkPylex(t, `br"raw"`, []pylexWant{{kind: 'S', text: `"raw"`, start: 0, end: 7, line: 0, last: 0}}, nil)
	checkPylex(t, `rf"{x}"`, []pylexWant{{kind: 'S', text: `"{x}"`, start: 0, end: 7, line: 0, last: 0}}, nil)
	// A name ending in a prefix letter followed by a quote is NOT a prefix when the whole
	// name is not one: the name and the string are separate tokens.
	checkPylex(t, `dur"..."`, []pylexWant{
		{kind: 'N', text: "dur", start: 0, end: 3, line: 0, last: 0},
		{kind: 'S', text: `"..."`, start: 3, end: 8, line: 0, last: 0},
	}, nil)
	checkPylex(t, `b2"0"`, []pylexWant{
		{kind: 'N', text: "b2", start: 0, end: 2, line: 0, last: 0},
		{kind: 'S', text: `"0"`, start: 2, end: 5, line: 0, last: 0},
	}, nil)
	// A prefix with no quote after it is just a name.
	checkPylex(t, "import r", []pylexWant{
		{kind: 'N', text: "import", start: 0, end: 6, line: 0, last: 0},
		{kind: 'N', text: "r", start: 7, end: 8, line: 0, last: 0},
	}, nil)
	// Case does not matter for the prefix lookup.
	checkPylex(t, `R"raw"`, []pylexWant{{kind: 'S', text: `"raw"`, start: 0, end: 6, line: 0, last: 0}}, nil)
	checkPylex(t, `BR"raw"`, []pylexWant{{kind: 'S', text: `"raw"`, start: 0, end: 7, line: 0, last: 0}}, nil)
}

func TestPyLexNumbers(t *testing.T) {
	checkPylex(t, "1.5", []pylexWant{{kind: '0', text: "1.5", start: 0, end: 3, line: 0, last: 0}}, nil)
	checkPylex(t, "0xdead_beef", []pylexWant{{kind: '0', text: "0xdead_beef", start: 0, end: 11, line: 0, last: 0}}, nil)
	// An exponent sign is not part of the number: the scanner stops at the '-'.
	checkPylex(t, "3e-2", []pylexWant{
		{kind: '0', text: "3e", start: 0, end: 2, line: 0, last: 0},
		{kind: 'O', text: "-", start: 2, end: 3, line: 0, last: 0},
		{kind: '0', text: "2", start: 3, end: 4, line: 0, last: 0},
	}, nil)
	// A leading-dot float: '.' followed by a digit is a number, not the operator path.
	checkPylex(t, ".5", []pylexWant{{kind: '0', text: ".5", start: 0, end: 2, line: 0, last: 0}}, nil)
	// A lone dot with a non-digit after it stays an operator.
	checkPylex(t, "x.y", []pylexWant{
		{kind: 'N', text: "x", start: 0, end: 1, line: 0, last: 0},
		{kind: 'O', text: ".", start: 1, end: 2, line: 0, last: 0},
		{kind: 'N', text: "y", start: 2, end: 3, line: 0, last: 0},
	}, nil)
}

func TestPyLexOperators(t *testing.T) {
	// The ellipsis is one token, and the scanner must not stop at its first dot.
	checkPylex(t, "...", []pylexWant{{kind: 'O', text: "...", start: 0, end: 3, line: 0, last: 0}}, nil)
	// Two-char operators: the comparison/shift/arrows and every assignment first letter.
	for _, op := range []string{"->", "**", "//", "<<", ">>", "+=", "-=", "*=", "/=", "%=",
		"&=", "|=", "^=", "@=", "!=", "<=", ">=", ":=", "=="} {
		checkPylex(t, op, []pylexWant{{kind: 'O', text: op, start: 0, end: len(op), line: 0, last: 0}}, nil)
	}
	// Single-char operators, including every char in the assignment-op first-letter set.
	for _, op := range []string{"=", "!", "<", ">", ":", "+", "-", "*", "/", "%", "&", "|", "^", "@", "(", ")", "[", "]", "{", "}", ",", "."} {
		checkPylex(t, op, []pylexWant{{kind: 'O', text: op, start: 0, end: 1, line: 0, last: 0}}, nil)
	}
}
