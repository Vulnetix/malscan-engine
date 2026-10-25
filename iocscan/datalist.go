package iocscan

import (
	"net"
	"regexp"
	"strings"
)

// ── Data lists and DNS records ───────────────────────────────────────────────
//
// A package that ships a table of addresses or hosts is carrying data, not naming a server it
// talks to: a crawler allow-list (`'66.249.68.128/27',` × 30), a Tor exit list, a CIDR table for
// a cloud provider, a resolver or root-server table, a host map (`'a.root-servers.net' =>
// '198.41.0.4',`), a blocklist of ad domains. Every element of such a list that a feed carries
// matches, and in the 2026-10-26 GCVE malware audit these lists were the largest shape among the
// withdrawn IOC-STIX-MATCH lines that still fired after the allowlist fixes.
//
// A bare address or host hit inside a list block is demoted to ClassContext. It is still recorded,
// so a list of real C2 addresses still corroborates; it cannot mint alone. A url hit, and an
// address or host that sits inside a URL on the line, keeps full weight: a list of
// `http://1.2.3.4/x` strings is a list of endpoints, not of data.

// minListLiterals is the number of distinct address/host literals a block must carry. Malware that
// hard-codes its C2 names one to three endpoints; the withdrawn lists carry 5 to several hundred.
const minListLiterals = 5

// listLiteralRe matches an address or CIDR literal, optionally with a :port. IPv6 is validated
// separately because its candidate shape is too loose for a token test.
var listLiteralRe = regexp.MustCompile(`^(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?::\d{1,5})?$`)

// listHostRe matches a bare host-name literal (optionally a `*.` wildcard or a trailing root dot).
var listHostRe = regexp.MustCompile(`(?i)^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\.?$`)

// listValueWords are the scalar values a list or map element carries next to its key.
var listValueWords = map[string]bool{
	"true": true, "false": true, "nil": true, "null": true, "none": true, "yes": true, "no": true,
}

// isListLiteral reports whether tok is an address, CIDR or host literal.
func isListLiteral(tok string) bool {
	if tok == "" {
		return false
	}
	if listLiteralRe.MatchString(tok) {
		return true
	}
	if strings.Count(tok, ":") >= 2 {
		if _, _, err := net.ParseCIDR(tok); err == nil {
			return true
		}
		return net.ParseIP(tok) != nil
	}
	return listHostRe.MatchString(tok)
}

// stripTrailingComment drops a `//` or `#` comment that starts outside a quoted string and after
// whitespace (so `http://x` and `#{interp}` are untouched).
func stripTrailingComment(s string) string {
	var q byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if q != 0 {
			if c == '\\' {
				i++
			} else if c == q {
				q = 0
			}
			continue
		}
		switch c {
		case '"', '\'', '`':
			q = c
		case '/', '#':
			if c == '/' && (i+1 >= len(s) || s[i+1] != '/') {
				continue
			}
			if i == 0 || s[i-1] == ' ' || s[i-1] == '\t' {
				return s[:i]
			}
		}
	}
	return s
}

// listElement reports whether line is wholly one element (or a few elements) of a literal list or
// map: once its comment is removed, every token outside quotes is an address/host literal, a
// number, a scalar keyword or list punctuation. It returns the literals it carries (quoted strings
// that are wholly a literal, plus bare literals). `"8.26.56.26": true, // Comodo`,
// `'66.249.68.128/27',`, `'a.root-servers.net' => '198.41.0.4',`, `134.195.4.2` and
// `"8.8.8.8", "4.2.2.4", "94.140.14.14",` all qualify; `ip := net.ParseIP("1.2.3.4")` does not.
func listElement(line string) (bool, []string) {
	s := stripTrailingComment(line)
	var lits []string
	var bare strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '"' && c != '\'' && c != '`' {
			bare.WriteByte(c)
			continue
		}
		j := i + 1
		for j < len(s) && s[j] != c {
			if s[j] == '\\' {
				j++
			}
			j++
		}
		if j >= len(s) {
			return false, nil // unterminated string: not a self-contained element
		}
		if v := s[i+1 : j]; isListLiteral(v) {
			lits = append(lits, v)
		}
		bare.WriteByte(' ')
		i = j
	}
	for _, tok := range strings.FieldsFunc(bare.String(), func(r rune) bool {
		return strings.ContainsRune(" \t[]{}(),;=>", r)
	}) {
		t := strings.TrimSuffix(tok, ":")
		switch {
		case t == "":
		case isListLiteral(t):
			lits = append(lits, t)
		case listValueWords[strings.ToLower(t)], isNumber(t):
		default:
			return false, nil
		}
	}
	return len(lits) > 0, lits
}

func isNumber(t string) bool {
	if t == "" {
		return false
	}
	for i := 0; i < len(t); i++ {
		if (t[i] < '0' || t[i] > '9') && t[i] != '.' && t[i] != '-' && t[i] != '_' {
			return false
		}
	}
	return true
}

var (
	listQuotedRe = regexp.MustCompile("\"(?:[^\"\\\\]|\\\\.)*\"|'(?:[^'\\\\]|\\\\.)*'|`[^`]*`")
	listDigitsRe = regexp.MustCompile(`\d+`)
)

// listSkeleton is line with quoted strings emptied and digits collapsed, so the rows of a
// generated table (`Prefix: netip.MustParsePrefix("1.178.1.0/24"),` × 50) share one skeleton.
func listSkeleton(line string) string {
	s := listQuotedRe.ReplaceAllString(strings.TrimSpace(stripTrailingComment(line)), `""`)
	return listDigitsRe.ReplaceAllString(s, "0")
}

// quotedLiterals returns the quoted strings on line that are wholly an address/host literal.
func quotedLiterals(line string) []string {
	var out []string
	for _, q := range listQuotedRe.FindAllString(line, -1) {
		if v := q[1 : len(q)-1]; isListLiteral(v) {
			out = append(out, v)
		}
	}
	return out
}

// dataLists marks which lines of a text sit inside a data-list block (see the section comment).
// A block is a run of consecutive list rows — whole literal elements (listElement), or lines that
// share a skeleton with the row before or after them and carry a quoted literal — through which
// blank and comment lines pass without breaking it. A block counts once it holds minListLiterals
// distinct literals. Computed lazily: nil until a hit needs it.
type dataLists struct {
	lines []string
	mark  []bool
	done  bool
}

func (d *dataLists) in(i int) bool {
	if !d.done {
		d.mark = markDataLists(d.lines)
		d.done = true
	}
	return d.mark[i]
}

func markDataLists(lines []string) []bool {
	n := len(lines)
	row := make([]bool, n)
	lits := make([][]string, n)
	skel := make([]string, n)
	for i, l := range lines {
		if len(l) > 2000 { // minified or generated blob: the minified-line rule owns it
			continue
		}
		if ok, ls := listElement(l); ok {
			row[i], lits[i] = true, ls
			continue
		}
		if ql := quotedLiterals(l); len(ql) > 0 {
			lits[i] = ql
			skel[i] = listSkeleton(l)
		}
	}
	// A table row shares its skeleton with the nearest row above or below it, looking past the
	// blank, comment and lone-bracket lines a struct-literal table puts between rows.
	neighbour := func(i, step int) int {
		for j := i + step; j >= 0 && j < n; j += step {
			if !passThrough(lines[j]) {
				return j
			}
		}
		return -1
	}
	for i := 0; i < n; i++ {
		if row[i] || skel[i] == "" {
			continue
		}
		if p := neighbour(i, -1); p >= 0 && skel[p] == skel[i] {
			row[i] = true
		} else if q := neighbour(i, 1); q >= 0 && skel[q] == skel[i] {
			row[i] = true
		}
	}
	mark := make([]bool, n)
	for i := 0; i < n; {
		if !row[i] {
			i++
			continue
		}
		distinct := map[string]bool{}
		j := i
		last := i
		for j < n && (row[j] || passThrough(lines[j])) {
			if row[j] {
				for _, v := range lits[j] {
					distinct[strings.ToLower(v)] = true
				}
				last = j
			}
			j++
		}
		if len(distinct) >= minListLiterals {
			for k := i; k <= last; k++ {
				mark[k] = row[k]
			}
		}
		i = last + 1
	}
	return mark
}

// passThrough reports whether a line inside a list block neither ends it nor counts toward it: a
// blank line, a comment, or a lone bracket line.
func passThrough(line string) bool {
	t := strings.TrimSpace(line)
	if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "//") || strings.HasPrefix(t, ";") {
		return true
	}
	return strings.Trim(t, "{}[](),;") == ""
}

// dataHit reports whether a text hit on line i is data rather than an endpoint: a bare address
// or host (not a url hit, not inside a URL on the line) that is a DNS record's RDATA or sits in a
// data-list block.
func dataHit(mm lineMatch, lists *dataLists, i int) bool {
	if mm.typ == TypeURL || mm.inURL {
		return false
	}
	return mm.zoneRecord || lists.in(i)
}

// zoneRecordTailRe matches the text before the address in a DNS resource record:
// `A.ROOT-SERVERS.NET.      3600000      A     ` or `foo.github.io. 300 IN A `. The owner name
// ends in a root dot or the record carries a TTL and the IN class, so prose ("at. A 1.2.3.4")
// does not qualify.
var zoneRecordTailRe = regexp.MustCompile(`(?i)(?:\.\s+\d+\s+(?:IN\s+)?|\.\s+IN\s+|\s\d+\s+IN\s+)(?:A|AAAA)\s+$`)

// ipInZoneRecord reports whether the address at s[start:] is the RDATA of a DNS A/AAAA record in
// zone-file syntax: a root hints file, a dig answer, a dns.NewRR fixture. A record names what a
// zone says a host resolves to; the package is not connecting there.
func ipInZoneRecord(s string, start int) bool {
	return zoneRecordTailRe.MatchString(s[:start])
}
