package iocscan

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// tind is a compact test indicator used to assemble STIX bundles.
type tind struct {
	pattern string
	name    string
	desc    string
	labels  []string
	extID   string
}

// makeBundle assembles a minimal but realistic STIX 2.1 bundle (with the
// marking-definition + identity objects the real feeds carry) around the given
// indicators.
func makeBundle(inds ...tind) string {
	objs := []map[string]any{
		{"type": "marking-definition", "id": "marking-definition--m", "definition_type": "statement"},
		{"type": "identity", "id": "identity--i", "name": "Vulnetix", "identity_class": "organization"},
	}
	for i, ind := range inds {
		obj := map[string]any{
			"type":         "indicator",
			"id":           "indicator--" + strconv.Itoa(i),
			"pattern":      ind.pattern,
			"pattern_type": "stix",
			"name":         ind.name,
			"description":  ind.desc,
			"labels":       ind.labels,
			"valid_from":   "2026-04-17T07:52:09Z",
			"external_references": []map[string]any{
				{"source_name": "vulnetix", "external_id": ind.extID},
			},
		}
		objs = append(objs, obj)
	}
	b, _ := json.Marshal(map[string]any{"type": "bundle", "id": "bundle--b", "objects": objs})
	return string(b)
}

// buildIndex marshals an index.json referencing the given feeds.
func buildIndex(base string, feeds []Feed) string {
	b, _ := json.Marshal(Index{
		BaseURL:   base,
		Feeds:     feeds,
		Generated: "2026-06-26T06:01:06Z",
		License:   "AGPL-3.0-or-later",
	})
	return string(b)
}

// stixTestServer is an in-memory STIX feed origin with hit counters and a
// mutable index/feed set, for hermetic fetch+cache tests.
type stixTestServer struct {
	*httptest.Server
	mu        sync.Mutex
	indexHits int
	feedHits  int
	indexBody string
	bodies    map[string]string // request path -> body
}

func newStixTestServer(t *testing.T) *stixTestServer {
	t.Helper()
	s := &stixTestServer{bodies: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if r.URL.Path == "/index.json" {
			s.indexHits++
			if s.indexBody == "" {
				http.NotFound(w, r)
				return
			}
			_, _ = io.WriteString(w, s.indexBody)
			return
		}
		body, ok := s.bodies[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		s.feedHits++
		_, _ = io.WriteString(w, body)
	})
	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

// feedEntry registers a feed body and returns its index entry (URL + sha256).
func (s *stixTestServer) feedEntry(eco, kind, body string) Feed {
	s.mu.Lock()
	path := "/" + eco + "/" + kind + ".stix.json"
	s.bodies[path] = body
	s.mu.Unlock()
	return Feed{
		Ecosystem: eco,
		Kind:      kind,
		URL:       s.URL + path,
		SHA256:    sha256Hex([]byte(body)),
		Count:     1,
	}
}

func (s *stixTestServer) setIndex(body string) {
	s.mu.Lock()
	s.indexBody = body
	s.mu.Unlock()
}

func (s *stixTestServer) hits() (index, feeds int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.indexHits, s.feedHits
}

func (s *stixTestServer) indexURL() string { return s.URL + "/index.json" }

// clock is a controllable time source for the loader's `now` seam.
type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }

// writeFile creates basedir/rel (with parents) holding content.
func writeFile(t *testing.T, basedir, rel, content string) string {
	t.Helper()
	full := filepath.Join(basedir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return full
}

// standardFeeds wires the generic + npm dns/urls feeds used across scan tests,
// sets the server index, and returns a FeedLoader bound to cacheDir + clk.
func standardLoader(t *testing.T, cacheDir string, clk *clock) (*stixTestServer, *FeedLoader) {
	t.Helper()
	s := newStixTestServer(t)
	genericDNS := makeBundle(
		tind{
			pattern: "[domain-name:value = 'evil-malware.io']",
			name:    "Malicious domain evil-malware.io",
			labels:  []string{"malicious-activity", "source:osm", "severity:critical", "ecosystem:generic"},
			extID:   "OSM-2026-001",
		},
		tind{
			pattern: "[ipv4-addr:value = '185.100.157.127']",
			name:    "Malicious IP 185.100.157.127",
			labels:  []string{"malicious-activity", "severity:high"},
			extID:   "OSM-2026-002",
		},
	)
	genericURLs := makeBundle(tind{
		pattern: "[url:value = 'http://evil-malware.io/payload']",
		name:    "Malicious URL",
		labels:  []string{"severity:critical"},
		extID:   "OSM-2026-003",
	})
	npmDNS := makeBundle(tind{
		pattern: "[domain-name:value = 'npm-bad.io']",
		name:    "Malicious npm domain",
		labels:  []string{"ecosystem:npm", "severity:high"},
		extID:   "OSM-2026-004",
	})
	npmURLs := makeBundle(tind{
		pattern: "[url:value = 'http://npm-bad.io/x']",
		name:    "Malicious npm URL",
		labels:  []string{"ecosystem:npm"},
		extID:   "OSM-2026-005",
	})
	feeds := []Feed{
		s.feedEntry("generic", "dns", genericDNS),
		s.feedEntry("generic", "urls", genericURLs),
		s.feedEntry("npm", "dns", npmDNS),
		s.feedEntry("npm", "urls", npmURLs),
	}
	s.setIndex(buildIndex(s.URL, feeds))

	loader := &FeedLoader{
		IndexURL:   s.indexURL(),
		CacheDir:   cacheDir,
		TTL:        time.Hour,
		HTTPClient: s.Client(),
		// Keep these index/feed tests hermetic — the TweetFeed base feed is
		// exercised separately in tweetfeed_test.go against a local server.
		DisableTweetFeed: true,
		now:              clk.now,
	}
	return s, loader
}

func newClock() *clock {
	return &clock{t: time.Date(2026, 6, 26, 12, 0, 0, 0, time.UTC)}
}

func glob(t *testing.T, dir, pattern string) []string {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// writeBytes writes raw bytes to basedir/rel (with parents).
func writeBytes(t *testing.T, basedir, rel string, data []byte) {
	t.Helper()
	full := filepath.Join(basedir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// findEvidence returns the first evidence matching relPath suffix, type, and
// value, or nil.
func findEvidence(r *Report, relPath string, typ IndicatorType, value string) *Evidence {
	for i := range r.Evidence {
		e := &r.Evidence[i]
		if e.RelPath == filepath.FromSlash(relPath) && e.IndicatorType == typ && e.IndicatorValue == value {
			return e
		}
	}
	return nil
}

// evidenceSummary renders the evidence list for test failure messages.
func evidenceSummary(r *Report) string {
	var b strings.Builder
	b.WriteString("[")
	for i, e := range r.Evidence {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(e.RelPath)
		b.WriteString(":")
		b.WriteString(string(e.IndicatorType))
		b.WriteString("=")
		b.WriteString(e.IndicatorValue)
	}
	b.WriteString("]")
	return b.String()
}
