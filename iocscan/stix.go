// Package iocscan adds a network-and-filesystem detection capability to the
// malscan-engine: it pulls domain / IP / URL indicators-of-compromise from
// Vulnetix's public STIX 2.1 feeds, then scans a working directory (and,
// optionally, ELF binaries within it) for any file that references a known-bad
// indicator, returning evidence with full context (host, filesystem path, and
// the file content around the hit).
//
// Unlike the detect package — which is a pure content analyzer operating on
// pre-loaded strings — iocscan performs I/O: it fetches the feeds over HTTPS and
// caches them to the OS temp directory. It remains STANDALONE and STATELESS:
// every Scan / Load call is self-contained, the only persistent side effect is
// the shared on-disk feed cache, and operational notices (a stale cache, a
// checksum mismatch) are RETURNED in the result as Warnings rather than logged —
// the engine owns no logger. This makes the package equally usable by the CLI
// and by the vdb-manager processors across every registry.
//
// This file holds the STIX bundle model and the parser that turns a bundle into
// an IndicatorSet with O(1) value lookups.
package iocscan

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/vulnetix/malscan-engine/allow"
)

// IndicatorType is the kind of observable a STIX indicator describes. Only the
// four kinds the feeds emit are modelled.
type IndicatorType string

const (
	TypeDomain IndicatorType = "domain" // domain-name:value
	TypeIPv4   IndicatorType = "ipv4"   // ipv4-addr:value
	TypeIPv6   IndicatorType = "ipv6"   // ipv6-addr:value
	TypeURL    IndicatorType = "url"    // url:value
)

// ExternalRef is one STIX external_reference (provenance for an indicator).
type ExternalRef struct {
	SourceName string `json:"source_name,omitempty"`
	ExternalID string `json:"external_id,omitempty"`
	URL        string `json:"url,omitempty"`
}

// Indicator is one parsed STIX indicator: the observable value plus the
// metadata we surface as evidence provenance.
type Indicator struct {
	Type         IndicatorType // domain | ipv4 | ipv6 | url
	Value        string        // the observable value (e.g. "evil.example", "185.100.157.127")
	Name         string        // STIX `name`
	Description  string        // STIX `description`
	Severity     string        // parsed from the `severity:<x>` label, if present
	Ecosystem    string        // parsed from the `ecosystem:<x>` label, if present
	Labels       []string      // STIX `labels`
	ExternalRefs []ExternalRef // STIX `external_references`
	ValidFrom    string        // STIX `valid_from`
}

// stixBundle / stixObject mirror the subset of STIX 2.1 we read. Fields we do
// not use are left out; unknown JSON keys are ignored by encoding/json.
type stixBundle struct {
	Type    string       `json:"type"`
	ID      string       `json:"id"`
	Objects []stixObject `json:"objects"`
}

type stixObject struct {
	Type               string        `json:"type"`
	Pattern            string        `json:"pattern"`
	PatternType        string        `json:"pattern_type"`
	Name               string        `json:"name"`
	Description        string        `json:"description"`
	Labels             []string      `json:"labels"`
	ExternalReferences []ExternalRef `json:"external_references"`
	ValidFrom          string        `json:"valid_from"`
}

// patternRe extracts the observable type and value from a single-comparison STIX
// pattern such as `[domain-name:value = 'evil.example']`. The feeds emit one
// comparison per indicator; OR/AND-combined patterns are not used and would be
// skipped (no match).
var patternRe = regexp.MustCompile(`\[(domain-name|ipv4-addr|ipv6-addr|url):value\s*=\s*'([^']*)'\]`)

// observableTypeMap maps a STIX object-path prefix to our IndicatorType.
var observableTypeMap = map[string]IndicatorType{
	"domain-name": TypeDomain,
	"ipv4-addr":   TypeIPv4,
	"ipv6-addr":   TypeIPv6,
	"url":         TypeURL,
}

// parseBundle unmarshals a STIX 2.1 bundle and returns its indicators. Non-
// indicator objects (marking-definition, identity) and indicators whose pattern
// is not a recognised single-value comparison are skipped without error.
func parseBundle(data []byte) ([]*Indicator, error) {
	var b stixBundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parse stix bundle: %w", err)
	}
	out := make([]*Indicator, 0, len(b.Objects))
	for _, o := range b.Objects {
		if o.Type != "indicator" {
			continue
		}
		ind := indicatorFromPattern(o.Pattern)
		if ind == nil {
			continue
		}
		ind.Name = o.Name
		ind.Description = o.Description
		ind.Labels = o.Labels
		ind.ExternalRefs = o.ExternalReferences
		ind.ValidFrom = o.ValidFrom
		ind.Severity = labelValue(o.Labels, "severity")
		ind.Ecosystem = labelValue(o.Labels, "ecosystem")
		out = append(out, ind)
	}
	return out, nil
}

// indicatorFromPattern parses a STIX comparison pattern into an Indicator with
// only Type and Value set, or nil if the pattern is not a recognised
// single-value domain/ip/url comparison.
func indicatorFromPattern(pattern string) *Indicator {
	m := patternRe.FindStringSubmatch(pattern)
	if m == nil {
		return nil
	}
	t, ok := observableTypeMap[m[1]]
	if !ok {
		return nil
	}
	val := strings.TrimSpace(m[2])
	if val == "" {
		return nil
	}
	return &Indicator{Type: t, Value: val}
}

// labelValue returns the value of the first `key:value` label (case-insensitive
// key match), or "" if absent. STIX labels here look like "severity:critical",
// "ecosystem:npm".
func labelValue(labels []string, key string) string {
	prefix := strings.ToLower(key) + ":"
	for _, l := range labels {
		if strings.HasPrefix(strings.ToLower(l), prefix) {
			return l[len(prefix):]
		}
	}
	return ""
}

// IndicatorSet is a merged, indexed collection of indicators with O(1) lookup by
// value. Keys are lowercased so matching is case-insensitive (domains and URLs
// are not case-sensitive in the host portion; IPs are unaffected).
type IndicatorSet struct {
	domains map[string]*Indicator
	ips     map[string]*Indicator
	urls    map[string]*Indicator
}

// NewIndicatorSet returns an empty set ready to Add / Merge into.
func NewIndicatorSet() *IndicatorSet {
	return &IndicatorSet{
		domains: make(map[string]*Indicator),
		ips:     make(map[string]*Indicator),
		urls:    make(map[string]*Indicator),
	}
}

// Add inserts one indicator, keyed by its lowercased value. A duplicate value of
// the same kind keeps the first occurrence (feeds may repeat across ecosystems).
//
// Benign indicators (reserved/placeholder IPs, package-registry/CDN/standards/docs
// domains — see the allow package) are dropped here so they never enter the match
// set: a still-polluted feed cannot produce IOC-STIX-MATCH false positives at scan
// time, and lookups stay fast.
func (s *IndicatorSet) Add(ind *Indicator) {
	if ind == nil || ind.Value == "" {
		return
	}
	if allow.Benign(string(ind.Type), ind.Value) {
		return
	}
	switch ind.Type {
	case TypeDomain:
		// Drop code-token-collision domains (a.top, this.global, …) so the feed
		// can't flag JS property access as a hostname.
		if allow.CodeTokenDomain(ind.Value) {
			return
		}
		key := domainKey(ind.Value)
		if _, ok := s.domains[key]; !ok {
			s.domains[key] = ind
		}
	case TypeIPv4, TypeIPv6:
		// Drop version/coordinate-shaped IPv4 (all octets <=31).
		if allow.VersionLikeIP(ind.Value) {
			return
		}
		key := ipKey(ind.Value)
		if _, ok := s.ips[key]; !ok {
			s.ips[key] = ind
		}
	case TypeURL:
		// Drop benign docs/homepage URLs on non-payload-capable hosts.
		if allow.BenignDocURL(ind.Value) {
			return
		}
		key := strings.ToLower(ind.Value)
		if _, ok := s.urls[key]; !ok {
			s.urls[key] = ind
		}
	}
}

// AddAll inserts every indicator in inds.
func (s *IndicatorSet) AddAll(inds []*Indicator) {
	for _, ind := range inds {
		s.Add(ind)
	}
}

// LookupDomain returns the indicator for an exact (case-insensitive) domain, or
// nil.
func (s *IndicatorSet) LookupDomain(domain string) *Indicator {
	return s.domains[domainKey(domain)]
}

// LookupIP returns the indicator for an IP (v4 or v6), normalising the format so
// e.g. "2001:db8::1" and "2001:0db8:0000:0000:0000:0000:0000:0001" match, or nil.
func (s *IndicatorSet) LookupIP(ip string) *Indicator {
	return s.ips[ipKey(ip)]
}

// domainKey normalises a domain for case-insensitive lookup: lowercased, with a
// trailing root dot stripped.
func domainKey(domain string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
}

// ipKey normalises an IP to its canonical net.IP string when parseable, else a
// lowercased trim. This makes IP matching insensitive to zero-padding and
// compression differences.
func ipKey(v string) string {
	v = strings.TrimSpace(v)
	if ip := net.ParseIP(v); ip != nil {
		return ip.String()
	}
	return strings.ToLower(v)
}

// LookupURL returns the indicator for an exact (case-insensitive) URL, or nil.
func (s *IndicatorSet) LookupURL(u string) *Indicator {
	return s.urls[strings.ToLower(u)]
}

// Len reports the total number of indicators across all kinds.
func (s *IndicatorSet) Len() int {
	return len(s.domains) + len(s.ips) + len(s.urls)
}

// Empty reports whether the set holds no indicators.
func (s *IndicatorSet) Empty() bool { return s.Len() == 0 }
