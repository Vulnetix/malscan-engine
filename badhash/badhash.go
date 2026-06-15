// Package badhash provides a case-insensitive set of known-bad artifact hashes
// for malicious-package detection. It is seeded from an embedded list and is
// designed to be augmented at runtime with the authoritative known-bad hashes
// stored in the shared database as MalwareIoc file-hash rows.
//
// This package is deliberately dependency-free (stdlib only) so it can be lifted
// into the shared Vulnetix detection module and consumed by both the VDB
// processors and the package-firewall.
package badhash

import (
	"bufio"
	_ "embed"
	"strings"
)

//go:embed data/known-bad-hashes.txt
var embedded string

// Set is a set of known-bad hashes keyed by lowercase hex digest. The zero value
// is not usable; construct with New.
type Set struct {
	m map[string]struct{}
}

// New returns a Set seeded from the embedded known-bad-hash list.
func New() *Set {
	s := &Set{m: make(map[string]struct{})}
	s.addLines(embedded)
	return s
}

func (s *Set) addLines(text string) {
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Trim any trailing "  comment", ",source", or "# note".
		if i := strings.IndexAny(line, " \t,#"); i >= 0 {
			line = line[:i]
		}
		s.Add(line)
	}
}

// Add inserts one hash, normalised to lowercase hex. Non-hash tokens (SKIP,
// short strings, non-hex) are ignored.
func (s *Set) Add(hash string) {
	if h := normalize(hash); h != "" {
		s.m[h] = struct{}{}
	}
}

// AddAll inserts many hashes (e.g. file-hash IOCs loaded from the database).
func (s *Set) AddAll(hashes []string) {
	for _, h := range hashes {
		s.Add(h)
	}
}

// Has reports whether hash matches a known-bad hash.
func (s *Set) Has(hash string) bool {
	h := normalize(hash)
	if h == "" {
		return false
	}
	_, ok := s.m[h]
	return ok
}

// Len returns the number of known-bad hashes in the set.
func (s *Set) Len() int { return len(s.m) }

// normalize lowercases, strips an algorithm prefix, and validates that the token
// is a plausible hex digest (>= 32 hex chars, i.e. md5 or stronger). It returns
// "" for anything that is not a hash so callers can pass raw checksum-array
// tokens (including "SKIP") without pre-filtering.
func normalize(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimPrefix(h, "sha256:")
	h = strings.TrimPrefix(h, "sha512:")
	h = strings.Trim(h, `'"`)
	if len(h) < 32 {
		return ""
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return ""
		}
	}
	return h
}
