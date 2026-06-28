package iocscan

import (
	"testing"
	"time"
)

const (
	twDomain = "tweet-c2-host.net"
	twIP     = "45.61.139.20"
	twSHA256 = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	twMD5    = "0123456789abcdef0123456789abcdef"
)

// tweetFeedBundle is a TweetFeed-shaped STIX 2.1 bundle: domain/url/ipv4
// indicators (for the IndicatorSet) + SHA-256 (quoted algo) and MD5 (bare algo)
// file-hash indicators (for badhash).
func tweetFeedBundle() string {
	return makeBundle(
		tind{pattern: "[domain-name:value = '" + twDomain + "']", name: "tw domain", labels: []string{"phishing"}},
		tind{pattern: "[url:value = 'http://" + twDomain + "/x']", name: "tw url", labels: []string{"malware"}},
		tind{pattern: "[ipv4-addr:value = '" + twIP + "']", name: "tw ip", labels: []string{"c2"}},
		tind{pattern: "[file:hashes.'SHA-256' = '" + twSHA256 + "']", name: "tw sha"},
		tind{pattern: "[file:hashes.MD5 = '" + twMD5 + "']", name: "tw md5"},
	)
}

// tweetLoader builds a server (index + one generic feed + the TweetFeed bundle)
// and a loader with the TweetFeed base pointed at that server.
func tweetLoader(t *testing.T, cacheDir string, clk *clock) (*stixTestServer, *FeedLoader) {
	t.Helper()
	s := newStixTestServer(t)
	genericDNS := makeBundle(tind{pattern: "[domain-name:value = 'evil-malware.io']", name: "g", labels: []string{"severity:high"}})
	s.setIndex(buildIndex(s.URL, []Feed{s.feedEntry("generic", "dns", genericDNS)}))
	s.mu.Lock()
	s.bodies["/tweetfeed.json"] = tweetFeedBundle()
	s.mu.Unlock()
	loader := &FeedLoader{
		IndexURL:     s.indexURL(),
		CacheDir:     cacheDir,
		TTL:          time.Hour,
		HTTPClient:   s.Client(),
		TweetFeedURL: s.URL + "/tweetfeed.json",
		now:          clk.now,
	}
	return s, loader
}

func TestParseTweetFeed(t *testing.T) {
	inds, hashes, err := parseTweetFeed([]byte(tweetFeedBundle()))
	if err != nil {
		t.Fatalf("parseTweetFeed: %v", err)
	}
	if len(inds) != 3 {
		t.Fatalf("indicators = %d, want 3 (domain/url/ipv4)", len(inds))
	}
	if len(hashes) != 2 {
		t.Fatalf("hashes = %d, want 2 (sha256+md5)", len(hashes))
	}
	got := map[string]bool{}
	for _, h := range hashes {
		got[h] = true
	}
	if !got[twSHA256] || !got[twMD5] {
		t.Fatalf("extracted hashes missing expected values: %v", hashes)
	}
}

func TestLoadMergesTweetFeedBase(t *testing.T) {
	_, loader := tweetLoader(t, t.TempDir(), newClock())
	set, warns, err := loader.Load("npm")
	if err != nil {
		t.Fatalf("Load: %v (warns %+v)", err, warns)
	}
	if set.LookupDomain("evil-malware.io") == nil {
		t.Fatal("missing vulnetix generic indicator")
	}
	if set.LookupDomain(twDomain) == nil {
		t.Fatal("TweetFeed base domain not merged into the set")
	}
	if set.LookupIP(twIP) == nil {
		t.Fatal("TweetFeed base ip not merged into the set")
	}
}

func TestTweetFeedHashes(t *testing.T) {
	_, loader := tweetLoader(t, t.TempDir(), newClock())
	hashes, w, err := loader.TweetFeedHashes(false)
	if err != nil {
		t.Fatalf("TweetFeedHashes: %v (warn %+v)", err, w)
	}
	if len(hashes) != 2 {
		t.Fatalf("hashes = %d, want 2", len(hashes))
	}
}

func TestTweetFeedOfflineNonFatal(t *testing.T) {
	s, loader := tweetLoader(t, t.TempDir(), newClock())
	// Point TweetFeed at a missing path (404) with no cache: its load fails, but
	// the overall Load must still succeed from the index feeds (base feed is
	// non-fatal / non-blocking).
	loader.TweetFeedURL = s.URL + "/does-not-exist.json"
	set, warns, err := loader.Load("npm")
	if err != nil {
		t.Fatalf("Load must not fail when only TweetFeed is unavailable: %v", err)
	}
	if set.LookupDomain("evil-malware.io") == nil {
		t.Fatal("index indicators should still load")
	}
	if !hasWarning(warns, "feed-error", tweetFeedSlug) {
		t.Fatalf("expected a non-fatal TweetFeed feed-error warning, got %+v", warns)
	}
	if set.LookupDomain(twDomain) != nil {
		t.Fatal("TweetFeed domain should be absent when its fetch failed")
	}
}

func TestRefreshForceFreshBypassesTTL(t *testing.T) {
	clk := newClock()
	s, loader := tweetLoader(t, t.TempDir(), clk)

	if _, _, err := loader.Load("npm"); err != nil {
		t.Fatalf("cold Load: %v", err)
	}
	idx0, feeds0 := s.hits()

	// Warm Load within TTL: no new fetches (cache hit for index + feeds + tweetfeed).
	if _, _, err := loader.Load("npm"); err != nil {
		t.Fatalf("warm Load: %v", err)
	}
	if idx1, feeds1 := s.hits(); idx1 != idx0 || feeds1 != feeds0 {
		t.Fatalf("warm load refetched: idx %d->%d feeds %d->%d", idx0, idx1, feeds0, feeds1)
	}

	// Refresh bypasses the TTL → index + npm-scope feeds + tweetfeed all refetched.
	clk.add(time.Minute) // advance so rewritten cache files get a distinct timestamp
	warns, err := loader.Refresh("npm")
	if err != nil {
		t.Fatalf("Refresh: %v (warns %+v)", err, warns)
	}
	idx2, feeds2 := s.hits()
	if idx2 <= idx0 {
		t.Fatalf("Refresh did not refetch the index (hits %d->%d)", idx0, idx2)
	}
	if feeds2 <= feeds0 {
		t.Fatalf("Refresh did not refetch feeds/tweetfeed (hits %d->%d)", feeds0, feeds2)
	}
}
