package iocscan

import (
	"strings"
	"testing"
	"time"
)

func TestFeedLoaderColdFetchAndCacheHit(t *testing.T) {
	cacheDir := t.TempDir()
	clk := newClock()
	s, loader := standardLoader(t, cacheDir, clk)

	// Cold load: index + 4 feeds (generic dns/urls + npm dns/urls).
	set, warns, err := loader.Load("npm")
	if err != nil {
		t.Fatalf("cold Load: %v", err)
	}
	if len(warns) != 0 {
		t.Fatalf("unexpected warnings on cold load: %+v", warns)
	}
	if set.LookupDomain("evil-malware.io") == nil || set.LookupDomain("npm-bad.io") == nil {
		t.Fatalf("merged set missing expected domains (len=%d)", set.Len())
	}
	if set.LookupIP("185.100.157.127") == nil {
		t.Fatal("merged set missing expected ip")
	}
	if idx, feeds := s.hits(); idx != 1 || feeds != 4 {
		t.Fatalf("after cold load hits = index:%d feeds:%d, want 1/4", idx, feeds)
	}

	// A timestamped cache file exists per slug.
	for _, slug := range []string{"index", "generic-dns", "generic-urls", "npm-dns", "npm-urls"} {
		if got := glob(t, cacheDir, "malscan-stix-"+slug+"-*.json"); len(got) != 1 {
			t.Fatalf("slug %q: %d cache files, want 1", slug, len(got))
		}
	}

	// Second load within TTL: pure cache hit, no new server requests.
	if _, _, err := loader.Load("npm"); err != nil {
		t.Fatalf("warm Load: %v", err)
	}
	if idx, feeds := s.hits(); idx != 1 || feeds != 4 {
		t.Fatalf("after warm load hits = index:%d feeds:%d, want still 1/4 (cache hit)", idx, feeds)
	}
}

func TestFeedLoaderTTLExpiryRefetchesAndPrunes(t *testing.T) {
	cacheDir := t.TempDir()
	clk := newClock()
	s, loader := standardLoader(t, cacheDir, clk)

	if _, _, err := loader.Load("npm"); err != nil {
		t.Fatalf("cold Load: %v", err)
	}

	// Past the TTL → everything refetched.
	clk.add(2 * time.Hour)
	if _, _, err := loader.Load("npm"); err != nil {
		t.Fatalf("post-ttl Load: %v", err)
	}
	if idx, feeds := s.hits(); idx != 2 || feeds != 8 {
		t.Fatalf("after ttl expiry hits = index:%d feeds:%d, want 2/8", idx, feeds)
	}

	// Prune keeps only the newest copy per slug.
	for _, slug := range []string{"index", "generic-dns", "npm-urls"} {
		if got := glob(t, cacheDir, "malscan-stix-"+slug+"-*.json"); len(got) != 1 {
			t.Fatalf("slug %q after refetch: %d cache files, want 1 (older pruned)", slug, len(got))
		}
	}
}

func TestFeedLoaderChecksumMismatchFallsBackToCache(t *testing.T) {
	cacheDir := t.TempDir()
	clk := newClock()
	s, loader := standardLoader(t, cacheDir, clk)

	// Prime the cache with good copies.
	if _, _, err := loader.Load("npm"); err != nil {
		t.Fatalf("cold Load: %v", err)
	}

	// Re-publish the index with a corrupted sha256 for one feed, then expire TTL.
	badFeeds := []Feed{
		{Ecosystem: "generic", Kind: "dns", URL: s.URL + "/generic/dns.stix.json", SHA256: strings.Repeat("0", 64)},
		{Ecosystem: "generic", Kind: "urls", URL: s.URL + "/generic/urls.stix.json", SHA256: sha256Hex([]byte(serveBody(t, s, "/generic/urls.stix.json")))},
		{Ecosystem: "npm", Kind: "dns", URL: s.URL + "/npm/dns.stix.json", SHA256: sha256Hex([]byte(serveBody(t, s, "/npm/dns.stix.json")))},
		{Ecosystem: "npm", Kind: "urls", URL: s.URL + "/npm/urls.stix.json", SHA256: sha256Hex([]byte(serveBody(t, s, "/npm/urls.stix.json")))},
	}
	s.setIndex(buildIndex(s.URL, badFeeds))
	clk.add(2 * time.Hour)

	set, warns, err := loader.Load("npm")
	if err != nil {
		t.Fatalf("post-mismatch Load: %v", err)
	}
	if !hasWarning(warns, "checksum-mismatch", "generic-dns") {
		t.Fatalf("expected checksum-mismatch warning for generic-dns, got %+v", warns)
	}
	// The cached good copy is still used → the domain is present.
	if set.LookupDomain("evil-malware.io") == nil {
		t.Fatal("expected fallback to cached generic-dns indicators")
	}
}

func TestFeedLoaderOfflineUsesStaleCache(t *testing.T) {
	cacheDir := t.TempDir()
	clk := newClock()
	s, loader := standardLoader(t, cacheDir, clk)

	if _, _, err := loader.Load("npm"); err != nil {
		t.Fatalf("cold Load: %v", err)
	}

	// Server goes away; cache goes stale.
	s.Close()
	clk.add(3 * time.Hour)

	set, warns, err := loader.Load("npm")
	if err != nil {
		t.Fatalf("offline Load with cache should succeed: %v", err)
	}
	if !hasWarningCode(warns, "stale-cache") {
		t.Fatalf("expected stale-cache warning, got %+v", warns)
	}
	if set.LookupDomain("evil-malware.io") == nil {
		t.Fatal("offline load should serve indicators from stale cache")
	}
	// The warning reports a positive age.
	for _, w := range warns {
		if w.Code == "stale-cache" && w.AgeSeconds <= 0 {
			t.Errorf("stale-cache warning age = %d, want > 0", w.AgeSeconds)
		}
	}
}

func TestFeedLoaderOfflineNoCacheErrors(t *testing.T) {
	s := newStixTestServer(t)
	// Register a valid index/feeds, then take the server down so nothing resolves.
	feeds := []Feed{s.feedEntry("generic", "dns", makeBundle(tind{pattern: "[domain-name:value = 'xbad.io']"}))}
	s.setIndex(buildIndex(s.URL, feeds))
	loader := &FeedLoader{
		IndexURL:         s.indexURL(),
		CacheDir:         t.TempDir(),
		TTL:              time.Hour,
		HTTPClient:       s.Client(),
		DisableTweetFeed: true,
		now:              newClock().now,
	}
	s.Close()

	if _, _, err := loader.Load("npm"); err == nil {
		t.Fatal("expected error when the index is unreachable and no cache exists")
	}
}

// ── helpers local to feed tests ─────────────────────────────────────────────

func serveBody(t *testing.T, s *stixTestServer, path string) string {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bodies[path]
}

func hasWarningCode(warns []Warning, code string) bool {
	for _, w := range warns {
		if w.Code == code {
			return true
		}
	}
	return false
}

func hasWarning(warns []Warning, code, feed string) bool {
	for _, w := range warns {
		if w.Code == code && w.Feed == feed {
			return true
		}
	}
	return false
}
