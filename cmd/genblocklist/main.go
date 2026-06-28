// Command genblocklist fetches public threat-intel feeds, parses their varied
// formats, de-duplicates, and writes the embedded badnet blocklists
// (badnet/data/bad-*.txt). It is run by `just gen-blocklists` and the pre-commit
// hook; it is deliberately resilient — a feed that fails to fetch logs a warning
// and is skipped, never aborting the run or wiping existing data.
package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const userAgent = "vulnetix-malscan-genblocklist/1.0 (+https://vulnetix.com)"

type kindFile struct {
	name   string // output filename
	label  string // header label
	getset func(*agg) map[string]struct{}
	getseq func(extracted) []string
}

// agg accumulates de-duplicated indicators across all feeds.
type agg struct {
	ipv4    map[string]struct{}
	ipv6    map[string]struct{}
	domains map[string]struct{}
	emails  map[string]struct{}
}

func newAgg() *agg {
	return &agg{
		ipv4:    map[string]struct{}{},
		ipv6:    map[string]struct{}{},
		domains: map[string]struct{}{},
		emails:  map[string]struct{}{},
	}
}

var kinds = []kindFile{
	{"bad-ipv4.txt", "known-bad IPv4 addresses (individual IPs only; no CIDR ranges)",
		func(a *agg) map[string]struct{} { return a.ipv4 }, func(e extracted) []string { return e.ipv4 }},
	{"bad-ipv6.txt", "known-bad IPv6 addresses (individual IPs only; no CIDR ranges)",
		func(a *agg) map[string]struct{} { return a.ipv6 }, func(e extracted) []string { return e.ipv6 }},
	{"bad-domains.txt", "known-bad hostnames/domains",
		func(a *agg) map[string]struct{} { return a.domains }, func(e extracted) []string { return e.domains }},
	{"bad-emails.txt", "known-bad threat-actor email addresses",
		func(a *agg) map[string]struct{} { return a.emails }, func(e extracted) []string { return e.emails }},
}

func main() {
	out := flag.String("out", "badnet/data", "output directory for the bad-*.txt files")
	force := flag.Bool("force", false, "regenerate even if existing data is fresh")
	noMerge := flag.Bool("no-merge", false, "rebuild from fetched feeds only (drop entries no longer present upstream)")
	maxAge := flag.Duration("max-age", 12*time.Hour, "skip regeneration when all data files are newer than this")
	timeout := flag.Duration("timeout", 30*time.Second, "per-feed HTTP timeout")
	flag.Parse()

	if !*force && fresh(*out, *maxAge) {
		fmt.Printf("genblocklist: data in %s is fresh (< %s); skipping. Use --force to override.\n", *out, *maxAge)
		return
	}

	a := newAgg()
	if !*noMerge {
		// Seed from existing data so a transiently-unreachable feed never drops
		// previously-collected indicators.
		for _, k := range kinds {
			if b, err := os.ReadFile(filepath.Join(*out, k.name)); err == nil {
				addLinesTo(k.getset(a), b)
			}
		}
	}

	client := &http.Client{Timeout: *timeout}
	ok, failed := 0, 0
	for _, f := range feeds {
		body, err := fetch(client, f.url)
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARN feed %s: %v (keeping existing data)\n", f.name, err)
			failed++
			continue
		}
		ex := parseFeed(f.format, body)
		mergeInto(a, ex)
		v4, v6, d, e := len(ex.ipv4), len(ex.ipv6), len(ex.domains), len(ex.emails)
		fmt.Printf("ok   %-30s ipv4=%-5d ipv6=%-4d domains=%-6d emails=%-5d\n", f.name, v4, v6, d, e)
		ok++
	}

	srcNames := make([]string, 0, len(feeds))
	for _, f := range feeds {
		srcNames = append(srcNames, f.name)
	}
	sort.Strings(srcNames)

	changed := 0
	for _, k := range kinds {
		vals := sortedSet(k.getset(a))
		content := renderFile(k.label, srcNames, vals)
		p := filepath.Join(*out, k.name)
		if wrote, err := writeIfChanged(p, content); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR writing %s: %v\n", p, err)
			os.Exit(1)
		} else if wrote {
			changed++
		}
		fmt.Printf("=> %-16s %d entries\n", k.name, len(vals))
	}

	fmt.Printf("genblocklist: %d feeds ok, %d failed, %d files changed\n", ok, failed, changed)
	if ok == 0 {
		fmt.Fprintln(os.Stderr, "WARN no feeds succeeded; existing data left unchanged")
	}
}

func mergeInto(a *agg, e extracted) {
	for _, v := range e.ipv4 {
		a.ipv4[v] = struct{}{}
	}
	for _, v := range e.ipv6 {
		a.ipv6[v] = struct{}{}
	}
	for _, v := range e.domains {
		a.domains[v] = struct{}{}
	}
	for _, v := range e.emails {
		a.emails[v] = struct{}{}
	}
}

// addLinesTo loads non-comment values from an existing data file into set.
func addLinesTo(set map[string]struct{}, b []byte) {
	for _, line := range lines(string(b)) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		set[line] = struct{}{}
	}
}

func fetch(c *http.Client, url string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", userAgent)
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

// fresh reports whether every data file exists and is newer than maxAge.
func fresh(dir string, maxAge time.Duration) bool {
	cutoff := time.Now().Add(-maxAge)
	for _, k := range kinds {
		info, err := os.Stat(filepath.Join(dir, k.name))
		if err != nil || info.ModTime().Before(cutoff) {
			return false
		}
	}
	return true
}

func sortedSet(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// renderFile builds the deterministic file body (stable header — no timestamp —
// so an unchanged indicator set yields a byte-identical file and a no-op diff).
func renderFile(label string, sources, vals []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n", label)
	b.WriteString("# GENERATED by cmd/genblocklist from public threat-intel feeds. Do not edit by hand.\n")
	b.WriteString("# Run `just gen-blocklists-force` to refresh.\n")
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
