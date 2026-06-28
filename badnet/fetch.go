package badnet

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// UserAgent identifies the fetcher to upstream feeds.
const UserAgent = "vulnetix-malscan-badnet/1.0 (+https://vulnetix.com)"

// DefaultFetchTimeout is the per-feed HTTP timeout used when the caller passes a
// nil client.
const DefaultFetchTimeout = 30 * time.Second

// dataFileNames is the on-disk layout of a definitions directory, shared by the
// embedded data, the generator, and the runtime overlay.
var dataFileNames = struct{ ipv4, ipv6, domains, emails string }{
	"bad-ipv4.txt", "bad-ipv6.txt", "bad-domains.txt", "bad-emails.txt",
}

// FeedResult reports the outcome of fetching one feed.
type FeedResult struct {
	Name    string
	OK      bool
	Err     string
	IPv4    int
	IPv6    int
	Domains int
	Emails  int
}

// Fetch downloads every configured threat-intel feed, parses each according to
// its format, and returns a Set of the de-duplicated, allow-filtered indicators
// plus a per-feed result. It is resilient: a feed that fails to fetch is recorded
// (OK=false) and skipped — Fetch never fails as a whole, so a few unreachable
// sources still yield a usable Set. A nil client gets a DefaultFetchTimeout one.
//
// This is the runtime path behind the CLI's `malscan --fetch-definitions`, giving
// customers fresh definitions without recompiling the engine.
func Fetch(ctx context.Context, client *http.Client) (*Set, []FeedResult) {
	return fetchFromFeeds(ctx, client, feeds)
}

// FetchWithFeedsFile downloads threat-intel feeds described by a caller-supplied
// feeds.json file, parses each according to its declared parser, and returns the
// same Set/result shape as Fetch. The file shape is:
//
//	{"schema_version":"badnet-feeds/v1","feeds":[{"key":"name","url":"https://...","parser":"iplist","enabled":true}]}
//
// Supported parser values are: iplist, netset, hosts, rss, emails, mixed, misp.
func FetchWithFeedsFile(ctx context.Context, client *http.Client, path string) (*Set, []FeedResult, error) {
	customFeeds, err := loadFeedsFile(path)
	if err != nil {
		return nil, nil, err
	}
	set, results := fetchFromFeeds(ctx, client, customFeeds)
	return set, results, nil
}

func fetchFromFeeds(ctx context.Context, client *http.Client, srcs []feed) (*Set, []FeedResult) {
	if client == nil {
		client = &http.Client{Timeout: DefaultFetchTimeout}
	}
	s := NewEmpty()
	s.sources = feedSourceNames(srcs)
	results := make([]FeedResult, 0, len(srcs))
	for _, f := range srcs {
		body, err := fetchURL(ctx, client, f.url)
		if err != nil {
			results = append(results, FeedResult{Name: f.name, Err: err.Error()})
			continue
		}
		ex := parseFeed(f.format, body)
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
		results = append(results, FeedResult{
			Name: f.name, OK: true,
			IPv4: len(ex.ipv4), IPv6: len(ex.ipv6), Domains: len(ex.domains), Emails: len(ex.emails),
		})
	}
	return s, results
}

func fetchURL(ctx context.Context, c *http.Client, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", UserAgent)
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return "", err
	}
	if len(b) == 0 {
		return "", fmt.Errorf("empty body")
	}
	return string(b), nil
}

// LoadDir loads a Set from a definitions directory laid out as bad-*.txt. Missing
// files are skipped (a partial or empty directory is not an error); only real
// read errors are returned. This is how the runtime overlay (written by Fetch +
// WriteFiles) is read back at scan time.
func LoadDir(dir string) (*Set, error) {
	s := NewEmpty()
	for _, name := range []string{dataFileNames.ipv4, dataFileNames.ipv6, dataFileNames.domains, dataFileNames.emails} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		s.addLines(string(b))
	}
	return s, nil
}

// WriteFiles writes the Set to dir as the four sorted, deduped bad-*.txt files
// (deterministic, timestamp-free headers so unchanged content is a no-op write).
// Returns the number of files whose content changed.
func (s *Set) WriteFiles(dir string) (changed int, err error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, err
	}
	files := []struct {
		name, label string
		vals        []string
	}{
		{dataFileNames.ipv4, "known-bad IPv4 addresses (individual IPs only; no CIDR ranges)", s.IPv4s()},
		{dataFileNames.ipv6, "known-bad IPv6 addresses (individual IPs only; no CIDR ranges)", s.IPv6s()},
		{dataFileNames.domains, "known-bad hostnames/domains", s.Domains()},
		{dataFileNames.emails, "known-bad threat-actor email addresses", s.Emails()},
	}
	srcs := s.sourceNames()
	for _, f := range files {
		content := renderFile(f.label, srcs, f.vals)
		p := filepath.Join(dir, f.name)
		wrote, werr := writeIfChanged(p, content)
		if werr != nil {
			return changed, werr
		}
		if wrote {
			changed++
		}
	}
	return changed, nil
}

// Merge folds every indicator from o into s.
func (s *Set) Merge(o *Set) {
	if o == nil {
		return
	}
	for k := range o.ipv4 {
		s.ipv4[k] = struct{}{}
	}
	for k := range o.ipv6 {
		s.ipv6[k] = struct{}{}
	}
	for k := range o.domains {
		s.domains[k] = struct{}{}
	}
	for k := range o.emails {
		s.emails[k] = struct{}{}
	}
	s.sources = mergeSources(s.sources, o.sources)
}

func feedNames() []string {
	return feedSourceNames(feeds)
}

func feedSourceNames(srcs []feed) []string {
	out := make([]string, len(srcs))
	for i, f := range srcs {
		out[i] = f.name
	}
	sort.Strings(out)
	return out
}

func (s *Set) sourceNames() []string {
	if len(s.sources) == 0 {
		return feedNames()
	}
	out := append([]string(nil), s.sources...)
	sort.Strings(out)
	return out
}

func mergeSources(a, b []string) []string {
	if len(a) == 0 {
		return append([]string(nil), b...)
	}
	if len(b) == 0 {
		return append([]string(nil), a...)
	}
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, src := range append(append([]string(nil), a...), b...) {
		if src == "" {
			continue
		}
		if _, ok := seen[src]; ok {
			continue
		}
		seen[src] = struct{}{}
		out = append(out, src)
	}
	sort.Strings(out)
	return out
}

func renderFile(label string, sources, vals []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n", label)
	b.WriteString("# GENERATED from public threat-intel feeds (badnet). Do not edit by hand.\n")
	b.WriteString("# Rebuild: `just gen-blocklists-force` (release) or `vulnetix malscan --fetch-definitions` (runtime).\n")
	fmt.Fprintf(&b, "# sources: %s\n", strings.Join(sources, ", "))
	fmt.Fprintf(&b, "# count: %d\n", len(vals))
	for _, v := range vals {
		b.WriteString(v)
		b.WriteByte('\n')
	}
	return b.String()
}

func writeIfChanged(path, content string) (bool, error) {
	if old, err := os.ReadFile(path); err == nil && string(old) == content {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, err
	}
	return true, os.WriteFile(path, []byte(content), 0o644)
}
