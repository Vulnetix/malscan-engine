package badnet

import (
	"encoding/json"
	"net"
	"regexp"
	"strings"

	"github.com/vulnetix/malscan-engine/allow"
)

// format identifies how a feed body is laid out so the right preprocessing runs
// before the shared classifier.
type format string

const (
	// fmtIPList: one IP/CIDR per line, optional trailing columns/comments
	// (dshield, binarydefense, cinsscore, bruteforceblocker, alienvault, isc cloudips).
	fmtIPList format = "iplist"
	// fmtNetset: firehol .netset — IP or CIDR per line, '#' comments.
	fmtNetset format = "netset"
	// fmtHosts: hosts-file — "0.0.0.0 domain" / "127.0.0.1 domain".
	fmtHosts format = "hosts"
	// fmtRSS: RSS/Atom XML — indicators live in element text.
	fmtRSS format = "rss"
	// fmtEmails: one email address per line.
	fmtEmails format = "emails"
	// fmtMixed: free-form text that may contain IPs and/or domains (isc intelfeed).
	fmtMixed format = "mixed"
	// fmtMISP: MISP-style JSON event ({"Event":{"Attribute":[{type,value}]}}),
	// e.g. the CrowdSec free feed — IP/domain indicators keyed by attribute type.
	fmtMISP format = "misp"
)

// extracted is the per-kind result of parsing one feed body.
type extracted struct {
	ipv4    []string
	ipv6    []string
	domains []string
	emails  []string
}

var (
	xmlTagRe    = regexp.MustCompile(`<[^>]+>`)
	cdataRe     = regexp.MustCompile(`<!\[CDATA\[(.*?)\]\]>`)
	ipv4Re      = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b`)
	ipv6Re      = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?:/\d{1,3})?\b`)
	domainTokRe = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b`)
	emailTokRe  = regexp.MustCompile(`(?i)\b[a-z0-9._%+\-]+@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b`)
)

// parseFeed extracts and de-classifies indicators from a feed body according to
// its format. Benign values (allow package) and CIDR ranges (anything but a bare
// host address) are dropped. The returned slices are de-duplicated within this
// feed; cross-feed dedup happens in the aggregator.
func parseFeed(f format, body string) extracted {
	var out extracted
	seen := map[string]struct{}{}
	add := func(bucket *[]string, key, val string) {
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		*bucket = append(*bucket, val)
	}

	switch f {
	case fmtMISP:
		parseMISP(body, &out, add)
		return out

	case fmtEmails:
		for _, line := range lines(body) {
			for _, e := range emailTokRe.FindAllString(line, -1) {
				if v := classifyEmail(e); v != "" {
					add(&out.emails, "e:"+v, v)
				}
			}
		}
		return out

	case fmtHosts:
		for _, line := range lines(body) {
			fields := strings.Fields(line)
			// hosts entries are "<sink-ip> <domain> [domain...]"; domains are the
			// trailing fields. A bare-domain line (no sink IP) is also accepted.
			start := 0
			if len(fields) >= 2 && net.ParseIP(fields[0]) != nil {
				start = 1
			}
			for _, tok := range fields[start:] {
				if d := classifyDomain(tok); d != "" {
					add(&out.domains, "d:"+d, d)
				}
			}
		}
		return out

	case fmtRSS:
		body = stripXML(body)
		// fall through to generic token extraction below.
		fallthrough
	case fmtMixed:
		for _, line := range lines(body) {
			collectIPs(line, &out, add)
			for _, d := range domainTokRe.FindAllString(line, -1) {
				if v := classifyDomain(d); v != "" {
					add(&out.domains, "d:"+v, v)
				}
			}
		}
		return out

	default: // fmtIPList, fmtNetset
		for _, line := range lines(body) {
			tok := firstToken(line)
			if tok == "" {
				continue
			}
			collectIPs(tok, &out, add)
		}
		return out
	}
}

// mispDoc is the subset of a MISP event JSON we read: the attribute type/value
// pairs. Unknown keys are ignored by encoding/json.
type mispDoc struct {
	Event struct {
		Attribute []mispAttribute `json:"Attribute"`
	} `json:"Event"`
}

type mispAttribute struct {
	Type    string    `json:"type"`
	Value   string    `json:"value"`
	ToIDS   *bool     `json:"to_ids"`
	Comment string    `json:"comment"`
	Tag     []mispTag `json:"Tag"`
}

type mispTag struct {
	Name string `json:"name"`
}

// parseMISP extracts indicators from a MISP-style JSON event. It accepts common
// network attribute types, skips non-IDS attributes, and drops CrowdSec-style
// benign scanner reputation before the shared allow/CIDR filters run.
func parseMISP(body string, out *extracted, add func(*[]string, string, string)) {
	var doc mispDoc
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		return
	}
	for _, attr := range doc.Event.Attribute {
		if attr.ToIDS != nil && !*attr.ToIDS {
			continue
		}
		if attr.benignReputation() {
			continue
		}
		collectMISPValue(attr.Type, attr.Value, out, add)
	}
}

func (a mispAttribute) benignReputation() bool {
	if strings.Contains(strings.ToLower(a.Comment), "reputation: benign") {
		return true
	}
	for _, tag := range a.Tag {
		if strings.EqualFold(tag.Name, "reputation:benign") {
			return true
		}
	}
	return false
}

func collectMISPValue(typ, val string, out *extracted, add func(*[]string, string, string)) {
	typ = strings.ToLower(strings.TrimSpace(typ))
	val = strings.TrimSpace(val)
	if val == "" {
		return
	}
	switch typ {
	case "ip-src", "ip-dst", "ip-src|port", "ip-dst|port", "domain|ip":
		collectIPs(val, out, add)
		if typ != "domain|ip" {
			return
		}
	case "email-src", "email-dst", "target-email", "whois-registrant-email":
		for _, e := range emailTokRe.FindAllString(val, -1) {
			if v := classifyEmail(e); v != "" {
				add(&out.emails, "e:"+v, v)
			}
		}
		return
	}
	for _, d := range domainTokRe.FindAllString(val, -1) {
		if v := classifyDomain(d); v != "" {
			add(&out.domains, "d:"+v, v)
		}
	}
}

// collectIPs finds IPv4/IPv6 tokens in s, keeping only individual addresses
// (CIDR ranges other than /32 or /128 are skipped) that are not benign.
func collectIPs(s string, out *extracted, add func(*[]string, string, string)) {
	for _, m := range ipv4Re.FindAllString(s, -1) {
		if v, isV6 := classifyIP(m); v != "" && !isV6 {
			add(&out.ipv4, "4:"+v, v)
		}
	}
	for _, m := range ipv6Re.FindAllString(s, -1) {
		if v, isV6 := classifyIP(m); v != "" && isV6 {
			add(&out.ipv6, "6:"+v, v)
		}
	}
}

// classifyIP validates an IP/CIDR token. CIDR ranges (prefix < full length) are
// rejected (individual IPs only). Benign IPs are rejected. Returns the canonical
// address and whether it is IPv6.
func classifyIP(tok string) (canonical string, isV6 bool) {
	tok = strings.Trim(strings.TrimSpace(tok), "[]")
	if tok == "" {
		return "", false
	}
	if slash := strings.IndexByte(tok, '/'); slash >= 0 {
		ip, ipnet, err := net.ParseCIDR(tok)
		if err != nil {
			return "", false
		}
		ones, bits := ipnet.Mask.Size()
		if ones != bits { // a real range, not a single host
			return "", false
		}
		tok = ip.String()
	}
	ip := net.ParseIP(tok)
	if ip == nil || allow.IP(ip.String()) {
		return "", false
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String(), false
	}
	return ip.String(), true
}

func classifyDomain(tok string) string {
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(tok)), ".")
	if d == "" || net.ParseIP(d) != nil { // not an IP
		return ""
	}
	if !domainTokRe.MatchString(d) {
		return ""
	}
	// FindAllString on the regex anchors loosely; require the whole token to match.
	if domainTokRe.FindString(d) != d {
		return ""
	}
	if allow.Domain(d) {
		return ""
	}
	return d
}

func classifyEmail(tok string) string {
	e := strings.ToLower(strings.TrimSpace(tok))
	if emailTokRe.FindString(e) != e {
		return ""
	}
	if at := strings.LastIndex(e, "@"); at >= 0 && allow.Domain(e[at+1:]) {
		return ""
	}
	return e
}

// firstToken returns the first whitespace/comment-delimited field of a line, or
// "" for a blank/comment line.
func firstToken(line string) string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
		return ""
	}
	if i := strings.IndexAny(line, " \t,;#"); i >= 0 {
		line = line[:i]
	}
	return strings.TrimSpace(line)
}

func lines(body string) []string {
	return strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n")
}

// stripXML unwraps CDATA and removes tags, leaving element text on which the
// generic token extractors run.
func stripXML(body string) string {
	body = cdataRe.ReplaceAllString(body, " $1 ")
	body = xmlTagRe.ReplaceAllString(body, " ")
	body = strings.ReplaceAll(body, "&lt;", "<")
	body = strings.ReplaceAll(body, "&gt;", ">")
	body = strings.ReplaceAll(body, "&amp;", "&")
	return body
}
