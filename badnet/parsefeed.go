package badnet

import (
	"fmt"
	"sort"
)

// Parsed is what one feed body yields after the same classification and
// allow-listing Fetch applies: single IPs (no CIDR ranges), valid domains and
// emails, benign values removed.
type Parsed struct {
	IPs     []string
	Domains []string
	Emails  []string
}

// ParseFeed parses one feed body in a named format: iplist, netset, hosts,
// rss, emails, mixed or misp, the parser keys of data/feeds.json. It lets a
// caller that fetches a feed itself (the Vulnetix site, serving indicators to
// runtime sensors) read it exactly as the malscan definitions do.
func ParseFeed(formatName, body string) (Parsed, error) {
	f, ok := parseFormat(formatName)
	if !ok {
		return Parsed{}, fmt.Errorf("unknown feed format %q", formatName)
	}
	ex := parseFeed(f, body)
	s := NewEmpty()
	for _, v := range ex.ipv4 {
		s.AddIP(v)
	}
	for _, v := range ex.ipv6 {
		s.AddIP(v)
	}
	for _, v := range ex.domains {
		s.AddDomain(v)
	}
	for _, v := range ex.emails {
		s.AddEmail(v)
	}
	var out Parsed
	for v := range s.ipv4 {
		out.IPs = append(out.IPs, v)
	}
	for v := range s.ipv6 {
		out.IPs = append(out.IPs, v)
	}
	for v := range s.domains {
		out.Domains = append(out.Domains, v)
	}
	for v := range s.emails {
		out.Emails = append(out.Emails, v)
	}
	sort.Strings(out.IPs)
	sort.Strings(out.Domains)
	sort.Strings(out.Emails)

	return out, nil
}
