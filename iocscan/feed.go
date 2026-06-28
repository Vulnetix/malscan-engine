package iocscan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// DefaultIndexURL is the public, unauthenticated STIX feed index. It lists, per
// ecosystem, the `dns` and `urls` STIX 2.1 bundle URLs plus their sha256.
const DefaultIndexURL = "https://vulnetix.com/malscan-stix/index.json"

// DefaultTTL is how long a cached feed copy is considered fresh.
const DefaultTTL = time.Hour

// cachePrefix is the common prefix of every on-disk cache file this package
// writes into the temp directory. Files are named
// "<cachePrefix><slug>-<unixNano>.json"; the timestamp is encoded so freshness
// is decided from the filename via a glob, with no sidecar metadata.
const cachePrefix = "malscan-stix-"

const defaultUserAgent = "malscan-engine"

// DefaultTweetFeedURL is the TweetFeed (0xDanielLopez) rolling 30-day STIX 2.1
// bundle — a base IOC feed (domain/url/ipv4 indicators + file hashes) merged
// into every load alongside the vulnetix.com index. It has no published checksum
// (a moving file), so it is fetched without sha verification.
const DefaultTweetFeedURL = "https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/stix/month.json"

// DefaultTweetFeedTTL is how long a cached TweetFeed copy is considered fresh.
const DefaultTweetFeedTTL = 24 * time.Hour

// defaultTweetFeedTimeout bounds the automatic (non-forced) TweetFeed fetch so a
// scan is never blocked: on connect/fetch timeout or offline the stale cache is
// used with a Warning, and a missing cache is skipped (also a Warning).
const defaultTweetFeedTimeout = 3 * time.Second

// tweetFeedSlug is the on-disk cache slug for the TweetFeed bundle.
const tweetFeedSlug = "tweetfeed"

// Feed is one entry in the index: a single ecosystem's DNS or URL bundle.
type Feed struct {
	Ecosystem string `json:"ecosystem"`
	Kind      string `json:"kind"` // "dns" | "urls"
	URL       string `json:"url"`
	SHA256    string `json:"sha256"`
	Count     int    `json:"count"`
}

// Index is the parsed index.json document.
type Index struct {
	BaseURL   string `json:"base_url"`
	Feeds     []Feed `json:"feeds"`
	Generated string `json:"generated"`
	License   string `json:"license"`
}

// FeedLoader fetches the STIX index and per-ecosystem feeds, caching each to the
// OS temp directory. It is safe to construct with the zero value: every field
// has a sensible default. The cache is shared across processes (and concurrent
// processors); writes are atomic (temp file + rename) so concurrent loaders do
// not corrupt one another.
type FeedLoader struct {
	IndexURL   string        // default DefaultIndexURL
	CacheDir   string        // default os.TempDir()
	TTL        time.Duration // default DefaultTTL (1h)
	HTTPClient *http.Client  // default 30s-timeout client
	UserAgent  string        // default "malscan-engine"

	// TweetFeed base feed, overridable by a consuming project WITHOUT recompiling
	// the module. TweetFeedURL "" uses DefaultTweetFeedURL; TweetFeedTTL/Timeout 0
	// use the defaults (24h / 3s); DisableTweetFeed skips the base feed entirely.
	TweetFeedURL     string
	TweetFeedTTL     time.Duration
	TweetFeedTimeout time.Duration
	DisableTweetFeed bool

	// now is a test seam for the clock; nil means time.Now. It governs both the
	// timestamp encoded into a new cache filename and the freshness comparison.
	now func() time.Time
}

func (l *FeedLoader) indexURL() string {
	if l.IndexURL != "" {
		return l.IndexURL
	}
	return DefaultIndexURL
}

func (l *FeedLoader) cacheDir() string {
	if l.CacheDir != "" {
		return l.CacheDir
	}
	return os.TempDir()
}

func (l *FeedLoader) ttl() time.Duration {
	if l.TTL > 0 {
		return l.TTL
	}
	return DefaultTTL
}

func (l *FeedLoader) userAgent() string {
	if l.UserAgent != "" {
		return l.UserAgent
	}
	return defaultUserAgent
}

func (l *FeedLoader) nowFn() time.Time {
	if l.now != nil {
		return l.now()
	}
	return time.Now()
}

func (l *FeedLoader) httpClient() *http.Client {
	if l.HTTPClient != nil {
		return l.HTTPClient
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (l *FeedLoader) tweetFeedURL() string {
	if l.TweetFeedURL != "" {
		return l.TweetFeedURL
	}
	return DefaultTweetFeedURL
}

func (l *FeedLoader) tweetFeedTTL() time.Duration {
	if l.TweetFeedTTL > 0 {
		return l.TweetFeedTTL
	}
	return DefaultTweetFeedTTL
}

func (l *FeedLoader) tweetFeedTimeout() time.Duration {
	if l.TweetFeedTimeout > 0 {
		return l.TweetFeedTimeout
	}
	return defaultTweetFeedTimeout
}

// tweetFeedClient bounds the TweetFeed fetch. The automatic path uses the short
// (3s) timeout so a scan is never blocked; an explicit force-fresh refresh uses
// the generous client since the caller is deliberately waiting for fresh data.
func (l *FeedLoader) tweetFeedClient(forceFresh bool) *http.Client {
	if forceFresh {
		return l.httpClient()
	}
	return &http.Client{Timeout: l.tweetFeedTimeout()}
}

// Load resolves the index, then fetches the `dns` and `urls` feeds for each
// requested ecosystem plus the always-included "generic" ecosystem, and merges
// them into one IndicatorSet. Every fresh/stale/checksum/feed condition is
// reported as a Warning (never logged). It returns an error only when the index
// itself cannot be obtained, or when no requested feed could be loaded at all.
func (l *FeedLoader) Load(ecosystems ...string) (*IndicatorSet, []Warning, error) {
	return l.load(false, false, ecosystems...)
}

// Refresh force-fetches every feed (the vulnetix index + its per-ecosystem feeds
// + the TweetFeed base) from remote, bypassing cache TTLs and rewriting the
// on-disk cache, so subsequent TTL-cached Load/Scan calls read the fresh data.
// With no ecosystems it refreshes every feed listed in the index; otherwise just
// the requested ecosystems (+ generic). It is the STIX half of a consuming
// project's "fetch fresh definitions" flow. Offline/timeout falls back to the
// stale cache with a Warning (non-blocking); the returned warnings explain each
// feed's outcome.
func (l *FeedLoader) Refresh(ecosystems ...string) ([]Warning, error) {
	_, warnings, err := l.load(true, len(ecosystems) == 0, ecosystems...)
	return warnings, err
}

// load is the shared implementation behind Load and Refresh. forceFresh bypasses
// every cache TTL (and rewrites the cache); wantAll fetches every feed in the
// index regardless of the requested ecosystems.
func (l *FeedLoader) load(forceFresh, wantAll bool, ecosystems ...string) (*IndicatorSet, []Warning, error) {
	var warnings []Warning

	idxData, w, err := l.acquire("index", l.indexURL(), "", l.ttl(), l.httpClient(), forceFresh)
	if err != nil {
		return nil, warnings, fmt.Errorf("load stix index: %w", err)
	}
	if w != nil {
		warnings = append(warnings, *w)
	}

	var idx Index
	if err := json.Unmarshal(idxData, &idx); err != nil {
		return nil, warnings, fmt.Errorf("parse stix index: %w", err)
	}

	wanted := wantedEcosystems(ecosystems)
	set := NewIndicatorSet()
	feedFailures := 0

	for _, feed := range idx.Feeds {
		if !wantAll && !wanted[feed.Ecosystem] {
			continue
		}
		slug := feed.Ecosystem + "-" + feed.Kind
		url := feed.URL
		if url == "" && idx.BaseURL != "" {
			url = strings.TrimRight(idx.BaseURL, "/") + "/" + feed.Ecosystem + "/" + feed.Kind + ".stix.json"
		}

		data, w, err := l.acquire(slug, url, feed.SHA256, l.ttl(), l.httpClient(), forceFresh)
		if err != nil {
			feedFailures++
			warnings = append(warnings, Warning{Code: "feed-error", Feed: slug, Message: err.Error()})
			continue
		}
		if w != nil {
			warnings = append(warnings, *w)
		}
		inds, perr := parseBundle(data)
		if perr != nil {
			feedFailures++
			warnings = append(warnings, Warning{Code: "parse-error", Feed: slug, Message: perr.Error()})
			continue
		}
		set.AddAll(inds)
	}

	// TweetFeed base feed — always merged unless disabled. NON-FATAL: a failure is
	// only a Warning (a base feed must never fail the load); offline/timeout uses
	// the stale cache via acquire, and a missing cache is skipped with a Warning.
	if inds, _, tw, terr := l.loadTweetFeed(forceFresh); terr != nil {
		warnings = append(warnings, Warning{Code: "feed-error", Feed: tweetFeedSlug, Message: terr.Error()})
	} else {
		if tw != nil {
			warnings = append(warnings, *tw)
		}
		set.AddAll(inds)
	}

	// If nothing loaded and at least one index feed failed, surface a hard error —
	// the caller asked for indicators and got none because acquisition failed.
	if set.Empty() && feedFailures > 0 {
		return set, warnings, fmt.Errorf("no stix feeds could be loaded (%d failed)", feedFailures)
	}

	return set, warnings, nil
}

// loadTweetFeed fetches + parses the TweetFeed base bundle (cached per
// tweetFeedTTL with the short timeout, or force-fresh with the generous client),
// returning its domain/url/ipv4 indicators and its file-hash strings. A disabled
// feed yields nothing; a fetch/parse failure is returned for the caller to
// downgrade to a Warning.
func (l *FeedLoader) loadTweetFeed(forceFresh bool) (inds []*Indicator, hashes []string, w *Warning, err error) {
	if l.DisableTweetFeed {
		return nil, nil, nil, nil
	}
	data, w, err := l.acquire(tweetFeedSlug, l.tweetFeedURL(), "", l.tweetFeedTTL(), l.tweetFeedClient(forceFresh), forceFresh)
	if err != nil {
		return nil, nil, w, err
	}
	inds, hashes, perr := parseTweetFeed(data)
	if perr != nil {
		return nil, nil, w, perr
	}
	return inds, hashes, w, nil
}

// TweetFeedHashes returns the file-hash (SHA-256/MD5) values from the TweetFeed
// base feed, for a consuming project to merge into its badhash set. forceFresh
// bypasses the cache TTL. Cache-backed, so calling it alongside Load/Scan does
// not trigger a second remote fetch within the TTL window.
func (l *FeedLoader) TweetFeedHashes(forceFresh bool) ([]string, *Warning, error) {
	_, hashes, w, err := l.loadTweetFeed(forceFresh)
	return hashes, w, err
}

// wantedEcosystems returns the set of ecosystems to load: every requested slug
// plus the always-included "generic" feed.
func wantedEcosystems(ecosystems []string) map[string]bool {
	wanted := map[string]bool{"generic": true}
	for _, e := range ecosystems {
		e = strings.TrimSpace(strings.ToLower(e))
		if e != "" {
			wanted[e] = true
		}
	}
	return wanted
}

// acquire returns the bytes for one cache slug, preferring a fresh cached copy,
// then a freshly fetched-and-verified copy, then the newest stale cached copy
// (with a Warning). It returns an error only when no copy can be obtained at all.
//
// expectedSHA, when non-empty, must match the sha256 of freshly fetched bytes;
// a mismatch is treated as a fetch failure (we fall back to cache if present).
func (l *FeedLoader) acquire(slug, url, expectedSHA string, ttl time.Duration, client *http.Client, forceFresh bool) ([]byte, *Warning, error) {
	newestPath, ts, found := l.cachedNewest(slug)

	// Fresh cache hit — use it silently. Skipped when forceFresh demands a refetch.
	if found && !forceFresh {
		if age := l.nowFn().Sub(ts); age < ttl {
			if data, err := os.ReadFile(newestPath); err == nil {
				return data, nil, nil
			}
			// fall through to refetch on read error
		}
	}

	// Need a fresh copy.
	data, ferr := l.fetch(url, client)
	if ferr == nil && expectedSHA != "" {
		if sum := sha256Hex(data); !strings.EqualFold(sum, expectedSHA) {
			ferr = &checksumError{url: url, want: expectedSHA, got: sum}
		}
	}
	if ferr == nil {
		if path, werr := l.writeCache(slug, data); werr == nil {
			l.prune(slug, path)
		}
		return data, nil, nil
	}

	// Fresh acquisition failed — fall back to the newest stale cache if any.
	if found {
		if data, rerr := os.ReadFile(newestPath); rerr == nil {
			age := l.nowFn().Sub(ts)
			code := "stale-cache"
			if isChecksumError(ferr) {
				code = "checksum-mismatch"
			}
			return data, &Warning{
				Code:       code,
				Feed:       slug,
				AgeSeconds: int(age.Seconds()),
				Message: fmt.Sprintf("using cached %s (age %s): %v",
					slug, age.Round(time.Second), ferr),
			}, nil
		}
	}

	return nil, nil, fmt.Errorf("fetch %s failed and no cache available: %w", url, ferr)
}

// fetch performs a single GET and returns the body, or an error for any non-200
// status or transport failure.
func (l *FeedLoader) fetch(url string, client *http.Client) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", l.userAgent())
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// cachedNewest returns the newest cache file for slug along with its encoded
// timestamp. found is false when no cache file exists.
func (l *FeedLoader) cachedNewest(slug string) (path string, ts time.Time, found bool) {
	pattern := filepath.Join(l.cacheDir(), cachePrefix+slug+"-*.json")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return "", time.Time{}, false
	}
	var bestPath string
	var bestTS time.Time
	for _, m := range matches {
		t, ok := parseCacheTimestamp(m, slug)
		if !ok {
			continue
		}
		if bestPath == "" || t.After(bestTS) {
			bestPath, bestTS = m, t
		}
	}
	if bestPath == "" {
		return "", time.Time{}, false
	}
	return bestPath, bestTS, true
}

// parseCacheTimestamp extracts the unix-nano timestamp encoded in a cache
// filename of the form "<cachePrefix><slug>-<unixNano>.json".
func parseCacheTimestamp(path, slug string) (time.Time, bool) {
	base := filepath.Base(path)
	prefix := cachePrefix + slug + "-"
	if !strings.HasPrefix(base, prefix) || !strings.HasSuffix(base, ".json") {
		return time.Time{}, false
	}
	tsStr := strings.TrimSuffix(strings.TrimPrefix(base, prefix), ".json")
	n, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(0, n), true
}

// writeCache atomically writes data to a new timestamped cache file and returns
// its path. The write is temp-file + rename so a concurrent reader never sees a
// partial file.
func (l *FeedLoader) writeCache(slug string, data []byte) (string, error) {
	dir := l.cacheDir()
	final := filepath.Join(dir, fmt.Sprintf("%s%s-%d.json", cachePrefix, slug, l.nowFn().UnixNano()))

	tmp, err := os.CreateTemp(dir, cachePrefix+"tmp-*.json")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return "", err
	}
	if err := os.Rename(tmpName, final); err != nil {
		os.Remove(tmpName)
		return "", err
	}
	return final, nil
}

// prune removes every cache file for slug except keep, so only the newest copy
// is retained. Failures are ignored — pruning is best-effort housekeeping.
func (l *FeedLoader) prune(slug, keep string) {
	pattern := filepath.Join(l.cacheDir(), cachePrefix+slug+"-*.json")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return
	}
	for _, m := range matches {
		if m == keep {
			continue
		}
		if _, ok := parseCacheTimestamp(m, slug); !ok {
			continue
		}
		os.Remove(m)
	}
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// checksumError marks a sha256 verification failure so acquire can label the
// resulting warning distinctly from a network failure.
type checksumError struct {
	url       string
	want, got string
}

func (e *checksumError) Error() string {
	return fmt.Sprintf("sha256 mismatch for %s: want %s got %s", e.url, e.want, e.got)
}

func isChecksumError(err error) bool {
	_, ok := err.(*checksumError)
	return ok
}
