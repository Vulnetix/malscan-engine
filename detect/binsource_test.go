package detect

import (
	"math/rand"
	"net"
	"sort"
	"strings"
	"testing"
)

// Property tests for registrableDomain, the eTLD+1 canonicalizer behind
// B-BIN-DOMAIN-MISMATCH and T-DIFF-SOURCE-DOMAIN-CHANGED. TestRegistrableDomain
// pins a dozen hosts; these properties must hold for any host, and a wrong
// eTLD+1 means a wrong verdict.

func TestRegistrableDomainProperties(t *testing.T) {
	seeds := []string{
		"beeper-desktop.download.beeper.com",
		"download.beeper.com",
		"pkg.sober-dev.app",
		"www.example.co.uk",
		"alice.github.io",
		"bucket.s3.amazonaws.com",
		"s3-eu-west-1.amazonaws.com",
		"gitlab.mpi-magdeburg.mpg.de",
		"github.com",
	}
	for _, h := range seeds {
		once := registrableDomain(h)
		if again := registrableDomain(once); again != once {
			t.Errorf("idempotence: registrableDomain(%q) = %q, registrableDomain again = %q", h, once, again)
		}
		// Subdomain collapse: any prefix labels, however deep, still reduce to the eTLD+1.
		for _, pre := range []string{"x", "a.b", "deep.sub"} {
			if got := registrableDomain(pre + "." + once); got != once {
				t.Errorf("subdomain collapse: registrableDomain(%q) = %q, want %q", pre+"."+once, got, once)
			}
		}
	}

	// Suffix-list completeness: every listed multi-label suffix is preserved at
	// the apex, so registrableDomain(host+suffix) is the host itself.
	suffixes := make([]string, 0, len(multiLabelSuffixes))
	for s := range multiLabelSuffixes {
		suffixes = append(suffixes, s)
	}
	sort.Strings(suffixes)
	for _, s := range suffixes {
		host := "example." + s
		if got := registrableDomain(host); got != host {
			t.Errorf("suffix completeness: registrableDomain(%q) = %q, want %q", host, got, host)
		}
	}

	// IP passthrough: a valid IP literal, v4 or v6, is returned as it is.
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 200; i++ {
		ip := net.IPv4(byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256))).String()
		if got := registrableDomain(ip); got != ip {
			t.Errorf("IPv4 passthrough: registrableDomain(%q) = %q", ip, got)
		}
	}
	for i := 0; i < 200; i++ {
		var b [16]byte
		for j := range b {
			b[j] = byte(r.Intn(256))
		}
		ip := net.IP(b[:]).String()
		if got := registrableDomain(ip); got != ip {
			t.Errorf("IPv6 passthrough: registrableDomain(%q) = %q", ip, got)
		}
	}
}

// FuzzRegistrableDomain runs arbitrary strings through the canonicalizer and
// checks idempotence. Inputs whose first pass leaves an empty or trailing-dot
// value (bare or doubled dots) have no eTLD+1 to pin and are skipped; everything
// else must be stable on the second application, and nothing may panic.
func FuzzRegistrableDomain(f *testing.F) {
	for _, seed := range []string{
		"beeper.com",
		"example.co.uk",
		"download.beeper.com",
		"beeper-desktop.download.beeper.com",
		"162.19.230.104",
		"2001:db8::1",
		"https://example.co.uk/beeper-1.0.AppImage",
		"www.example.co.uk",
		"alice.github.io",
		"",
		".",
		"localhost",
		"a..b.c",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, h string) {
		once := registrableDomain(h)
		if once == "" || strings.HasSuffix(once, ".") {
			return
		}
		if again := registrableDomain(once); again != once {
			t.Fatalf("idempotence: registrableDomain(%q) = %q, registrableDomain again = %q", h, once, again)
		}
	})
}
