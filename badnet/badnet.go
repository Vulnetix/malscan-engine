// Package badnet provides sets of known-bad network indicators — individual IPs
// (v4/v6), hostnames/domains, and threat-actor email addresses — aggregated from
// public threat-intel blocklists. It is seeded from embedded lists (regenerated
// by cmd/genblocklist) and can be augmented at runtime, mirroring the badhash
// package.
//
// The embedded data is deliberately individual IPs only (no CIDR ranges) and is
// pre-filtered against the allow package, so reserved/placeholder/registry values
// never enter the set. Lookups are O(1) map membership.
//
// Apart from the sibling allow package (the single source of truth for benign
// values) this package is dependency-free, so it can be lifted into the shared
// detection module and consumed by the CLI, the VDB processors, and the
// package-firewall alike.
package badnet

import (
	"bufio"
	"embed"
	"net"
	"regexp"
	"sort"
	"strings"

	"github.com/vulnetix/malscan-engine/allow"
)

//go:embed data
var dataFS embed.FS

var dataFiles = []string{
	"data/bad-ipv4.txt",
	"data/bad-ipv6.txt",
	"data/bad-domains.txt",
	"data/bad-emails.txt",
}

var (
	domainRe = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	emailRe  = regexp.MustCompile(`^[a-z0-9._%+\-]+@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
)

// Set is a collection of known-bad IPs, domains, and emails. The zero value is
// not usable; construct with New (or NewEmpty for a runtime-only set).
type Set struct {
	ipv4    map[string]struct{}
	ipv6    map[string]struct{}
	domains map[string]struct{}
	emails  map[string]struct{}
	sources []string
}

// NewEmpty returns an empty Set ready to Add into.
func NewEmpty() *Set {
	return &Set{
		ipv4:    map[string]struct{}{},
		ipv6:    map[string]struct{}{},
		domains: map[string]struct{}{},
		emails:  map[string]struct{}{},
	}
}

// New returns a Set seeded from the embedded blocklists.
func New() *Set {
	s := NewEmpty()
	for _, f := range dataFiles {
		b, err := dataFS.ReadFile(f)
		if err != nil {
			continue
		}
		s.addLines(string(b))
	}
	return s
}

func (s *Set) addLines(text string) {
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Defensive: take the first field, dropping any trailing comment/columns.
		if i := strings.IndexAny(line, " \t,#"); i >= 0 {
			line = line[:i]
		}
		s.Add(line)
	}
}

// Add classifies a single token as an email, IP, or domain and inserts it.
// Benign values (per the allow package) and malformed tokens are ignored.
func (s *Set) Add(tok string) {
	tok = strings.TrimSpace(tok)
	if tok == "" {
		return
	}
	switch {
	case strings.Contains(tok, "@"):
		s.AddEmail(tok)
	case net.ParseIP(strings.Trim(tok, "[]")) != nil:
		s.AddIP(tok)
	default:
		s.AddDomain(tok)
	}
}

// AddIP inserts a single IP (v4 or v6). CIDR notation and benign IPs are ignored.
func (s *Set) AddIP(v string) {
	v = strings.Trim(strings.TrimSpace(v), "[]")
	ip := net.ParseIP(v)
	if ip == nil || allow.IP(ip.String()) {
		return
	}
	if v4 := ip.To4(); v4 != nil {
		s.ipv4[v4.String()] = struct{}{}
		return
	}
	s.ipv6[ip.String()] = struct{}{}
}

// AddDomain inserts a hostname/domain (lowercased). Benign and malformed values
// are ignored.
func (s *Set) AddDomain(v string) {
	d := normDomain(v)
	if d == "" || !domainRe.MatchString(d) || allow.Domain(d) {
		return
	}
	s.domains[d] = struct{}{}
}

// AddEmail inserts a threat-actor email address (lowercased). Emails on benign
// hosts and malformed values are ignored.
func (s *Set) AddEmail(v string) {
	e := strings.ToLower(strings.TrimSpace(v))
	if !emailRe.MatchString(e) {
		return
	}
	if at := strings.LastIndex(e, "@"); at >= 0 && allow.Domain(e[at+1:]) {
		return
	}
	s.emails[e] = struct{}{}
}

// AddAll classifies and inserts each token.
func (s *Set) AddAll(toks []string) {
	for _, t := range toks {
		s.Add(t)
	}
}

// HasIP reports whether v matches a known-bad IP (format-insensitive).
func (s *Set) HasIP(v string) bool {
	ip := net.ParseIP(strings.Trim(strings.TrimSpace(v), "[]"))
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		_, ok := s.ipv4[v4.String()]
		return ok
	}
	_, ok := s.ipv6[ip.String()]
	return ok
}

// HasDomain reports whether v matches a known-bad domain (case-insensitive).
func (s *Set) HasDomain(v string) bool {
	_, ok := s.domains[normDomain(v)]
	return ok
}

// HasEmail reports whether v matches a known-bad email (case-insensitive).
func (s *Set) HasEmail(v string) bool {
	_, ok := s.emails[strings.ToLower(strings.TrimSpace(v))]
	return ok
}

// IPs returns every known-bad IP (v4 then v6), sorted.
func (s *Set) IPs() []string {
	out := append(keys(s.ipv4), keys(s.ipv6)...)
	sort.Strings(out)
	return out
}

// IPv4s returns every known-bad IPv4 address, sorted.
func (s *Set) IPv4s() []string { return sortedKeys(s.ipv4) }

// IPv6s returns every known-bad IPv6 address, sorted.
func (s *Set) IPv6s() []string { return sortedKeys(s.ipv6) }

// Domains returns every known-bad domain, sorted.
func (s *Set) Domains() []string { return sortedKeys(s.domains) }

// Emails returns every known-bad email, sorted.
func (s *Set) Emails() []string { return sortedKeys(s.emails) }

// Len returns the total number of indicators across all kinds.
func (s *Set) Len() int {
	return len(s.ipv4) + len(s.ipv6) + len(s.domains) + len(s.emails)
}

// Counts returns per-kind cardinalities (ipv4, ipv6, domains, emails).
func (s *Set) Counts() (ipv4, ipv6, domains, emails int) {
	return len(s.ipv4), len(s.ipv6), len(s.domains), len(s.emails)
}

func normDomain(v string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(v)), ".")
}

func keys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func sortedKeys(m map[string]struct{}) []string {
	out := keys(m)
	sort.Strings(out)
	return out
}
