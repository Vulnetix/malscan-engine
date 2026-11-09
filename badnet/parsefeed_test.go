package badnet

import (
	"fmt"
	"math/rand/v2"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/vulnetix/malscan-engine/allow"
)

// This file holds the round-trip property tests over ParseFeed, the exported
// re-parsing surface the Vulnetix site and the genblocklist generator share.
// The invariants come from the card; generators keep to values the validators
// classify, so any divergence between the per-bucket filters is what fails.

// rtValue is one canonical indicator value plus the bucket it belongs to.
type rtValue struct {
	kind string // "ip", "domain", "email"
	val  string
}

// rtIPs, rtDomains and rtEmails are the fixed corpus: valid, non-benign values
// every canonical render must round-trip.
var (
	rtIPs = []rtValue{
		{"ip", "45.137.21.9"},
		{"ip", "203.0.112.68"},
		{"ip", "185.220.101.245"},
		{"ip", "88.198.45.117"},
		{"ip", "2a00:23c1:abcd::12f:1"},
		{"ip", "2404:6800:4001::1"},
	}
	rtDomains = []rtValue{
		{"domain", "c2.evil-typo.xyz"},
		{"domain", "drop.malware-nest.online"},
		{"domain", "login.phishing-port.io"},
		{"domain", "mx.stealer-relay.dev"},
	}
	rtEmails = []rtValue{
		{"email", "scam@evil-c2.ru"},
		{"email", "drop.a@phish-bait.top"},
		{"email", "x.y+z@mail.stealer-relay.dev"},
	}
)

// allFormats is the full parser key set of data/feeds.json / parseFormat.
var allFormats = []format{fmtIPList, fmtNetset, fmtHosts, fmtRSS, fmtEmails, fmtMixed, fmtMISP}

// rtAllowlistedIPs and rtAllowDomains sample the reserved/example shapes the
// allow package promises never to mint.
var (
	rtAllowlistedIPs = []string{"8.8.8.8", "127.0.0.1", "203.0.113.7", "1.2.3.4", "10.0.0.5", "100.64.1.2", "192.0.2.9", "169.254.3.4", "224.0.0.5", "1.1.1.1", "2001:db8::dead:beef"}
	rtAllowDomains   = []string{"example.com", "github.com", "foo.example.org", "test.invalid", "docs.evil-typo.xyz", "www.example.net"}
	rtAllowEmails    = []string{"a@foo.example.org", "someone@example.com", "bob@gitlab.com"}
)

// rtRender returns the canonical one-line body entry a line-oriented format
// uses for a value's kind, or "" when that format's body carries no such kind.
// MISP is built separately in rtBody from JSON attributes.
func rtRender(f format, v rtValue) string {
	switch v.kind {
	case "ip":
		switch f {
		case fmtIPList, fmtNetset, fmtMixed, fmtRSS:
			return v.val
		}
	case "domain":
		switch f {
		case fmtHosts:
			return "0.0.0.0 " + v.val
		case fmtRSS, fmtMixed:
			return v.val
		}
	case "email":
		switch f {
		case fmtEmails:
			return v.val
		}
	}
	return ""
}

// rtBody renders exactly the given values into one format's canonical body.
// MISP gets a JSON attribute list; every other format is one value per line.
func rtBody(f format, ips, domains, emails []string) string {
	switch f {
	case fmtMISP:
		var b strings.Builder
		b.WriteString(`{"Event":{"Attribute":[`)
		first := true
		add := func(typ, val string) {
			if !first {
				b.WriteString(",")
			}
			first = false
			fmt.Fprintf(&b, `{"type":%q,"value":%q,"to_ids":true}`, typ, val)
		}
		for _, ip := range ips {
			add("ip-dst", ip)
		}
		for _, d := range domains {
			add("domain", d)
		}
		for _, e := range emails {
			add("email-src", e)
		}
		b.WriteString(`]}}`)
		return b.String()
	default:
		var lines []string
		for _, v := range rtValues(ips, domains, emails) {
			if s := rtRender(f, v); s != "" {
				lines = append(lines, s)
			}
		}
		return strings.Join(lines, "\n")
	}
}

// rtCorpusBody is rtBody over the fixed corpus.
func rtCorpusBody(f format) string {
	var ips, doms, mails []string
	for _, v := range rtIPs {
		ips = append(ips, v.val)
	}
	for _, v := range rtDomains {
		doms = append(doms, v.val)
	}
	for _, v := range rtEmails {
		mails = append(mails, v.val)
	}
	return rtBody(f, ips, doms, mails)
}

// rtSupported reports whether the format's canonical render carries v's kind at
// all: separate from rtRender, which only knows line-oriented syntaxes. MISP is
// the exception: its JSON attributes can carry every kind.
func rtSupported(f format, kind string) bool {
	switch kind {
	case "ip":
		return f == fmtIPList || f == fmtNetset || f == fmtMixed || f == fmtRSS || f == fmtMISP
	case "domain":
		return f == fmtHosts || f == fmtRSS || f == fmtMixed || f == fmtMISP
	case "email":
		return f == fmtEmails || f == fmtMISP
	}
	return false
}

func rtValues(ips, domains, emails []string) []rtValue {
	var out []rtValue
	for _, ip := range ips {
		out = append(out, rtValue{"ip", ip})
	}
	for _, d := range domains {
		out = append(out, rtValue{"domain", d})
	}
	for _, e := range emails {
		out = append(out, rtValue{"email", e})
	}
	return out
}

// rtClassify reports whether the format's canonical render of v survives the
// corresponding classifier, i.e. whether v belongs in the want-set for a body
// that carries it.
func rtClassify(f format, v rtValue) bool {
	if !rtSupported(f, v.kind) {
		return false
	}
	switch v.kind {
	case "ip":
		canon, _ := classifyIP(v.val)
		return canon != ""
	case "domain":
		return classifyDomain(v.val) != ""
	case "email":
		return classifyEmail(v.val) != ""
	}
	return false
}

// rtReParse re-parses a Parsed through the format's canonical render, the
// "parse(ParseFeed(...)) == ParseFeed(...)" side of the round trip.
func rtReParse(f format, p Parsed) (Parsed, error) {
	return ParseFeed(string(f), rtBody(f, p.IPs, p.Domains, p.Emails))
}

func TestParseFeedRoundTrip(t *testing.T) {
	for _, f := range allFormats {
		f := f
		t.Run(string(f), func(t *testing.T) {
			body := rtCorpusBody(f)
			if body == "" {
				t.Fatalf("%s: no canonical body", f)
			}
			p, err := ParseFeed(string(f), body)
			if err != nil {
				t.Fatalf("ParseFeed(%q): %v", f, err)
			}

			// Invariant 1: canonical round trip, parse(ParseFeed(...)) == ParseFeed(...)
			// per bucket.
			re, err := rtReParse(f, p)
			if err != nil {
				t.Fatalf("re-parse: %v", err)
			}
			if !slices.Equal(re.IPs, p.IPs) {
				t.Errorf("%s: IPs round trip: re-parse %v != %v", f, re.IPs, p.IPs)
			}
			if !slices.Equal(re.Domains, p.Domains) {
				t.Errorf("%s: domains round trip: re-parse %v != %v", f, re.Domains, p.Domains)
			}
			if !slices.Equal(re.Emails, p.Emails) {
				t.Errorf("%s: emails round trip: re-parse %v != %v", f, re.Emails, p.Emails)
			}

			checkSurvivors(t, string(f), p)
			checkNoBenign(t, string(f), p)
			checkNoCIDR(t, p)
		})
	}
}

// TestParseFeedBuckets pins the exact bucket each canonical value lands in per
// format: a format that cannot carry a kind must not grow that bucket.
func TestParseFeedBuckets(t *testing.T) {
	for _, f := range allFormats {
		for _, v := range append(slices.Clone(rtIPs), append(slices.Clone(rtDomains), rtEmails...)...) {
			if !rtSupported(f, v.kind) {
				continue
			}
			var ips, doms, mails []string
			switch v.kind {
			case "ip":
				ips = []string{v.val}
			case "domain":
				doms = []string{v.val}
			case "email":
				mails = []string{v.val}
			}
			p, err := ParseFeed(string(f), rtBody(f, ips, doms, mails))
			if err != nil {
				t.Fatalf("ParseFeed(%q, %q): %v", f, v.val, err)
			}
			var bucket []string
			switch v.kind {
			case "ip":
				bucket = p.IPs
			case "domain":
				bucket = p.Domains
			case "email":
				bucket = p.Emails
			}
			if !slices.Equal(bucket, []string{v.val}) {
				t.Errorf("%s + %s %q: got %v, want exactly [%q]", f, v.kind, v.val, bucket, v.val)
			}
		}
	}
}

// TestParseFeedNoBenignValues proves invariant 2 across formats: a benign value
// that reaches a body never comes out of Parsed, and never takes a good value
// down with it.
func TestParseFeedNoBenignValues(t *testing.T) {
	for _, f := range allFormats {
		for _, ip := range rtAllowlistedIPs {
			if rtRender(f, rtValue{"ip", ip}) == "" {
				continue
			}
			p, err := ParseFeed(string(f), rtBody(f, []string{ip, ip}, nil, nil))
			if err != nil {
				t.Fatalf("ParseFeed(%q, ip %q): %v", f, ip, err)
			}
			if n := countStr(p.IPs, ip); n != 0 {
				t.Errorf("%s: benign IP %q survived %d times in %v", f, ip, n, p.IPs)
			}
			p2, err := ParseFeed(string(f), rtBody(f, []string{ip, "45.137.21.9"}, nil, nil))
			if err != nil {
				t.Fatalf("ParseFeed(%q): %v", f, err)
			}
			if n := countStr(p2.IPs, ip); n != 0 {
				t.Errorf("%s: benign IP %q survived in %v", f, ip, p2.IPs)
			}
			if !hasStr(p2.IPs, "45.137.21.9") {
				t.Errorf("%s: good IP dropped alongside benign: %v", f, p2.IPs)
			}
		}
		for _, d := range rtAllowDomains {
			if rtRender(f, rtValue{"domain", d}) == "" {
				continue
			}
			p, err := ParseFeed(string(f), rtBody(f, nil, []string{d, d}, nil))
			if err != nil {
				t.Fatalf("ParseFeed(%q, domain %q): %v", f, d, err)
			}
			if n := countStr(p.Domains, d); n != 0 {
				t.Errorf("%s: benign domain %q survived %d times in %v", f, d, n, p.Domains)
			}
			p2, err := ParseFeed(string(f), rtBody(f, nil, []string{d, "c2.evil-typo.xyz"}, nil))
			if err != nil {
				t.Fatalf("ParseFeed(%q): %v", f, err)
			}
			if !hasStr(p2.Domains, "c2.evil-typo.xyz") {
				t.Errorf("%s: good domain dropped alongside benign: %v", f, p2.Domains)
			}
		}
		for _, e := range rtAllowEmails {
			p, err := ParseFeed(string(fmtEmails), e+"\n"+e+"\n")
			if err != nil {
				t.Fatalf("ParseFeed(emails, %q): %v", e, err)
			}
			if n := countStr(p.Emails, e); n != 0 {
				t.Errorf("emails: benign email %q survived in %v", e, p.Emails)
			}
		}
	}
}

// TestParseFeedNoCIDRSurvivors proves invariant 3: tokens with a prefix shorter
// than the full length are dropped, so no Parsed.IP contains "/".
func TestParseFeedNoCIDRSurvivors(t *testing.T) {
	cidrs := []string{
		"10.0.0.0/8", "45.137.21.0/24", "62.84.102.0/24",
		"2001:db8::/32", "2a00::/16", "185.220.101.245/32",
	}
	for _, f := range []format{fmtIPList, fmtNetset, fmtMixed, fmtRSS} {
		for _, c := range cidrs {
			p, err := ParseFeed(string(f), c+"\n"+c+"\n")
			if err != nil {
				t.Fatalf("ParseFeed(%q, %q): %v", f, c, err)
			}
			for _, ip := range p.IPs {
				if strings.Contains(ip, "/") {
					t.Errorf("%s: CIDR %q survived as %q", f, c, ip)
				}
			}
		}
	}
	// /32 and /128 keep the single host; its canonical form carries no slash.
	p, err := ParseFeed("iplist", "62.84.102.85/32\n2a00:23c1:abcd::12f:1/128\n")
	if err != nil {
		t.Fatalf("ParseFeed: %v", err)
	}
	for _, ip := range p.IPs {
		if strings.Contains(ip, "/") {
			t.Errorf("single-host CIDR canonicalised with a slash: %q", ip)
		}
	}
}

// TestParseFeedDedup proves invariant 4: the same value twice in one body yields
// a single Parsed entry per bucket.
func TestParseFeedDedup(t *testing.T) {
	for _, f := range allFormats {
		body := rtBody(f, []string{"45.137.21.9", "45.137.21.9"}, []string{"c2.evil-typo.xyz", "c2.evil-typo.xyz"}, []string{"scam@evil-c2.ru", "scam@evil-c2.ru"})
		if body == "" {
			continue
		}
		p, err := ParseFeed(string(f), body)
		if err != nil {
			t.Fatalf("ParseFeed(%q): %v", f, err)
		}
		if n := countStr(p.IPs, "45.137.21.9"); n > 1 {
			t.Errorf("%s: IP appears %d times in %v", f, n, p.IPs)
		}
		if n := countStr(p.Domains, "c2.evil-typo.xyz"); n > 1 {
			t.Errorf("%s: domain appears %d times in %v", f, n, p.Domains)
		}
		if n := countStr(p.Emails, "scam@evil-c2.ru"); n > 1 {
			t.Errorf("%s: email appears %d times in %v", f, n, p.Emails)
		}
	}
}

// TestParseFeedBucketsMatchValidators is the property driver: for a generated
// list of valid IPs, domains and emails, whatever lands in Parsed is exactly
// what the corresponding classify* accepts for the format, minus allow-listed
// values.
func TestParseFeedBucketsMatchValidators(t *testing.T) {
	rng := rand.New(rand.NewPCG(42, 7))
	for i := 0; i < 200; i++ {
		ips, doms, mails := rtGenerate(rng)
		for _, f := range allFormats {
			body := rtBody(f, ips, doms, mails)
			p, err := ParseFeed(string(f), body)
			if err != nil {
				t.Fatalf("ParseFeed(%q): %v", f, err)
			}
			wantIPs := map[string]bool{}
			wantDoms := map[string]bool{}
			wantMails := map[string]bool{}
			for _, v := range rtValues(ips, doms, mails) {
				if !rtClassify(f, v) {
					continue
				}
				switch v.kind {
				case "ip":
					wantIPs[v.val] = true
				case "domain":
					wantDoms[v.val] = true
				case "email":
					wantMails[v.val] = true
				}
			}
			for _, ip := range p.IPs {
				if !wantIPs[ip] {
					t.Errorf("%s: IP %q not among want-set %v (body %q)", f, ip, ips, body)
				}
				if allow.IP(ip) {
					t.Errorf("%s: benign IP %q survived", f, ip)
				}
			}
			for _, d := range p.Domains {
				if !wantDoms[d] {
					t.Errorf("%s: domain %q not among want-set %v (body %q)", f, d, doms, body)
				}
				if allow.Domain(d) {
					t.Errorf("%s: benign domain %q survived", f, d)
				}
			}
			for _, e := range p.Emails {
				if !wantMails[e] {
					t.Errorf("%s: email %q not among want-set %v (body %q)", f, e, mails, body)
				}
			}
			checkNoCIDR(t, p)
		}
	}
}

// TestParseFeedFixpoint re-parses what a generated body yields: the parse must
// be a fixpoint (parse(ParseFeed(...)) == ParseFeed(...)) per bucket.
func TestParseFeedFixpoint(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 50; i++ {
		ips, doms, mails := rtGenerate(rng)
		for _, f := range allFormats {
			body := rtBody(f, ips, doms, mails)
			p1, err := ParseFeed(string(f), body)
			if err != nil {
				t.Fatalf("ParseFeed(%q): %v", f, err)
			}
			re, err := rtReParse(f, p1)
			if err != nil {
				t.Fatalf("re-parse: %v", err)
			}
			if !slices.Equal(re.IPs, p1.IPs) {
				t.Fatalf("%s: IP fixpoint broken: %v -> %v", f, p1.IPs, re.IPs)
			}
			if !slices.Equal(re.Domains, p1.Domains) {
				t.Fatalf("%s: domain fixpoint broken: %v -> %v", f, p1.Domains, re.Domains)
			}
			if !slices.Equal(re.Emails, p1.Emails) {
				t.Fatalf("%s: email fixpoint broken: %v -> %v", f, p1.Emails, re.Emails)
			}
		}
	}
}

// rtGenerate returns a random mix of canonical valid values: public IPv4 and
// IPv6 addresses, plausible non-benign domains, and emails over them.
func rtGenerate(rng *rand.Rand) (ips, domains, emails []string) {
	for i := 0; i < 1+rng.IntN(4); i++ {
		ips = append(ips, rtRandIP(rng))
	}
	for i := 0; i < 1+rng.IntN(4); i++ {
		domains = append(domains, rtRandDomain(rng))
	}
	for i := 0; i < 1+rng.IntN(3); i++ {
		emails = append(emails, rtRandEmail(rng))
	}
	return ips, domains, emails
}

// rtRandIP builds a public IPv4 or IPv6 address that the allow package does not
// call benign, so "no benign values survive" is never vacuous on the generator
// side.
func rtRandIP(rng *rand.Rand) string {
	for attempt := 0; attempt < 32; attempt++ {
		var s string
		if rng.IntN(2) == 0 {
			s = fmt.Sprintf("%d.%d.%d.%d",
				45+rng.IntN(180), 1+rng.IntN(250), 1+rng.IntN(250), 1+rng.IntN(250))
		} else {
			s = fmt.Sprintf("2a0%d:%x::%x:%x", rng.IntN(8), rng.IntN(0x10000), rng.IntN(0x10000), rng.IntN(0x10000))
			if net.ParseIP(s) == nil {
				continue
			}
		}
		if !allow.IP(s) {
			return s
		}
	}
	return "45.137.21.9"
}

// rtRandDomain builds a domain that passes domainTokRe and is not benign.
func rtRandDomain(rng *rand.Rand) string {
	for attempt := 0; attempt < 32; attempt++ {
		d := rtLabel(rng) + "." + rtLabel(rng) + "." + []string{"xyz", "online", "top", "io", "dev"}[rng.IntN(5)]
		if !allow.Domain(d) {
			return d
		}
	}
	return "c2.evil-typo.xyz"
}

func rtLabel(rng *rand.Rand) string {
	n := 1 + rng.IntN(8)
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteByte("abcdefghijklmnopqrstuvwxyz"[rng.IntN(26)])
	}
	return b.String()
}

func rtRandEmail(rng *rand.Rand) string {
	local := rtLabel(rng)
	if rng.IntN(3) == 0 {
		local += "." + rtLabel(rng)
	}
	if rng.IntN(3) == 0 {
		local += "+tag"
	}
	return local + "@" + rtRandDomain(rng)
}

func countStr(xs []string, want string) int {
	n := 0
	for _, x := range xs {
		if x == want {
			n++
		}
	}
	return n
}

func checkSurvivors(t *testing.T, format string, p Parsed) {
	t.Helper()
	f, _ := parseFormat(format)
	for _, v := range append(slices.Clone(rtIPs), append(slices.Clone(rtDomains), rtEmails...)...) {
		if !rtSupported(f, v.kind) {
			continue
		}
		var bucket []string
		switch v.kind {
		case "ip":
			bucket = p.IPs
		case "domain":
			bucket = p.Domains
		case "email":
			bucket = p.Emails
		}
		if !hasStr(bucket, v.val) {
			t.Errorf("%s: %s %q missing from %v", format, v.kind, v.val, bucket)
		}
	}
}

func checkNoBenign(t *testing.T, format string, p Parsed) {
	t.Helper()
	for _, ip := range rtAllowlistedIPs {
		if hasStr(p.IPs, ip) {
			t.Errorf("%s: benign IP %q survived", format, ip)
		}
	}
	for _, d := range rtAllowDomains {
		if hasStr(p.Domains, d) {
			t.Errorf("%s: benign domain %q survived", format, d)
		}
	}
}

func checkNoCIDR(t *testing.T, p Parsed) {
	t.Helper()
	for _, ip := range p.IPs {
		if strings.Contains(ip, "/") {
			t.Errorf("CIDR range survived: %q", ip)
		}
	}
}

// FuzzParseFeed drives ParseFeed with arbitrary (format, body) pairs; nothing
// may panic, and the invariants hold for whatever comes out.
func FuzzParseFeed(f *testing.F) {
	for _, name := range allFormats {
		f.Add(string(name), "45.137.21.9\nc2.evil-typo.xyz\n")
	}
	f.Add("misp", `{"Event":{"Attribute":[{"type":"ip-src","value":"186.7.19.21","to_ids":true}]}}`)
	f.Add("misp", `{"Event":{"Attribute":[{"type":"ip-src","value":"not an ip","to_ids":false}]}}`)
	f.Add("misp", `{"Event":{"Attribute":[{"type":"domain|ip","value":"c2.badactor.net|45.137.21.9"}]}}`)
	f.Add("misp", `not json at all`)
	f.Add("misp", `{"Event":`)
	f.Add("misp", `{"Event":{"Attribute":[{"type":"email-src","value":"a@b.example.org","comment":"Reputation: benign"}]}}`)
	f.Add("iplist", "# comment\n1.2.3.0/24\n;semi\n62.84.102.85/32\n")
	f.Add("mixed", "http://user:pw@host.tld/path?x=1#frag\n2001:db8::1/64\n")
	f.Add("hosts", "\x00\x01\xff")
	f.Add("rss", "<![CDATA[ 185.100.157.127 ]]><title>a</title>")
	f.Add("", "")
	f.Add("nope", "185.220.101.9")

	f.Fuzz(func(t *testing.T, formatName, body string) {
		p, err := ParseFeed(formatName, body)
		if err != nil {
			if len(p.IPs) != 0 || len(p.Domains) != 0 || len(p.Emails) != 0 {
				t.Errorf("error path must return the zero Parsed, got %+v", p)
			}
			return
		}
		if strings.Contains(strings.Join(p.IPs, " "), "/") {
			t.Errorf("CIDR survived: %v", p.IPs)
		}
		for _, ip := range p.IPs {
			if allow.IP(ip) {
				t.Errorf("benign IP %q survived (body %q)", ip, body)
			}
		}
		for _, d := range p.Domains {
			if allow.Domain(d) {
				t.Errorf("benign domain %q survived (body %q)", d, body)
			}
		}
	})
}
