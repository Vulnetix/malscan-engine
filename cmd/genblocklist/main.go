// Command genblocklist fetches public threat-intel feeds, parses their varied
// formats, de-duplicates, and writes the embedded badnet blocklists
// (badnet/data/bad-*.txt). It is run by `just gen-blocklists` and the pre-commit
// hook; it is deliberately resilient — a feed that fails to fetch logs a warning
// and is skipped, never aborting the run or wiping existing data.
//
// The fetch/parse/build/write logic lives in the importable badnet package so the
// CLI can run the same refresh at runtime (`malscan --fetch-definitions`); this
// command is a thin wrapper that adds staleness-guarding and existing-data merge.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/vulnetix/malscan-engine/badnet"
)

var dataFiles = []string{"bad-ipv4.txt", "bad-ipv6.txt", "bad-domains.txt", "bad-emails.txt"}

func main() {
	out := flag.String("out", "badnet/data", "output directory for the bad-*.txt files")
	force := flag.Bool("force", false, "regenerate even if existing data is fresh")
	noMerge := flag.Bool("no-merge", false, "rebuild from fetched feeds only (drop entries no longer present upstream)")
	maxAge := flag.Duration("max-age", 12*time.Hour, "skip regeneration when all data files are newer than this")
	timeout := flag.Duration("timeout", badnet.DefaultFetchTimeout, "per-feed HTTP timeout")
	flag.Parse()

	if !*force && fresh(*out, *maxAge) {
		fmt.Printf("genblocklist: data in %s is fresh (< %s); skipping. Use --force to override.\n", *out, *maxAge)
		return
	}

	set, results := badnet.Fetch(context.Background(), &http.Client{Timeout: *timeout})
	ok, failed := 0, 0
	for _, r := range results {
		if r.OK {
			fmt.Printf("ok   %-30s ipv4=%-5d ipv6=%-4d domains=%-6d emails=%-5d\n", r.Name, r.IPv4, r.IPv6, r.Domains, r.Emails)
			ok++
		} else {
			fmt.Fprintf(os.Stderr, "WARN feed %s: %s (keeping existing data)\n", r.Name, r.Err)
			failed++
		}
	}

	if !*noMerge {
		// Union with existing data so a transiently-unreachable feed never drops
		// previously-collected indicators.
		if existing, err := badnet.LoadDir(*out); err == nil {
			set.Merge(existing)
		}
	}

	changed, err := set.WriteFiles(*out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR writing %s: %v\n", *out, err)
		os.Exit(1)
	}
	v4, v6, d, e := set.Counts()
	fmt.Printf("=> ipv4=%d ipv6=%d domains=%d emails=%d (%d files changed)\n", v4, v6, d, e, changed)
	fmt.Printf("genblocklist: %d feeds ok, %d failed\n", ok, failed)
	if ok == 0 {
		fmt.Fprintln(os.Stderr, "WARN no feeds succeeded; existing data left unchanged")
	}
}

// fresh reports whether every data file exists and is newer than maxAge.
func fresh(dir string, maxAge time.Duration) bool {
	cutoff := time.Now().Add(-maxAge)
	for _, name := range dataFiles {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || info.ModTime().Before(cutoff) {
			return false
		}
	}
	return true
}
