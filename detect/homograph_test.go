package detect

import (
	"math/rand/v2"
	"strings"
	"testing"
)

func findingByID(fs []Finding, id string) *Finding {
	for i := range fs {
		if fs[i].ID == id {
			return &fs[i]
		}
	}
	return nil
}

func TestHomographMixedScriptIsEvidence(t *testing.T) {
	// The aur-general example: Cyrillic і (U+0456) swapped into a Latin hostname.
	ctx := &PackageContext{PkgbuildContent: "source=(\"https://іnstall.example-clі.dev/payload.sh\")"}
	fs := analyzeHomograph(ctx)
	f := findingByID(fs, "P-HOMOGRAPH-MIXED-SCRIPT")
	if f == nil {
		t.Fatalf("expected mixed-script homograph finding, got %+v", fs)
	}
	if f.Class != ClassEvidence {
		t.Errorf("mixed-script should be evidence, got %s", f.Class)
	}
	if !IsMalicious(fs) {
		t.Error("a mixed-script source host should mint on its own")
	}
}

func TestHomographPunycodeIsContextOnly(t *testing.T) {
	ctx := &PackageContext{PkgbuildContent: "source=(\"http://xn--nstall-ovf.xn--example-cl-62i.dev/x\")"}
	fs := analyzeHomograph(ctx)
	f := findingByID(fs, "P-IDN-PUNYCODE-HOST")
	if f == nil {
		t.Fatalf("expected punycode finding, got %+v", fs)
	}
	if f.Class != ClassContext {
		t.Errorf("punycode should be context (legit IDN possible), got %s", f.Class)
	}
	if IsMalicious(fs) {
		t.Error("a punycode host alone must NOT mint")
	}
}

func TestHomographCleanURLsNoFinding(t *testing.T) {
	ctx := &PackageContext{
		PkgbuildContent: "source=(\"https://install.example-cli.dev/x.tgz\" \"git+https://github.com/owner/repo.git\")",
		Meta:            &PackageMeta{URL: "https://example.org", Source: []string{"https://files.pythonhosted.org/x.tar.gz"}},
	}
	if fs := analyzeHomograph(ctx); len(fs) != 0 {
		t.Errorf("clean ASCII URLs should produce no homograph finding, got %+v", fs)
	}
}

// randHost builds a random valid dotted host: lower-case ASCII labels (letters
// and digits, one starting with a letter), no empty label, no hyphen runs at
// the edges, and an all-letters TLD.
func randHost(rng *rand.Rand) string {
	var b strings.Builder
	n := 2 + rng.IntN(3)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte('.')
		}
		labelLen := 1 + rng.IntN(9)
		if i == n-1 {
			labelLen = 2 + rng.IntN(3) // TLD: letters only
		}
		for j := 0; j < labelLen; j++ {
			r := byte('a' + rng.IntN(26))
			if j > 0 && i < n-1 && rng.IntN(4) == 0 {
				r = byte('0' + rng.IntN(10))
			}
			b.WriteByte(r)
		}
	}
	return b.String()
}

func TestURLHostnameProperties(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 2000; i++ {
		host := randHost(rng)
		canon := urlHostname(host)
		if canon != host {
			t.Fatalf("urlHostname(%q) = %q, want the input back (it is already canonical)", host, canon)
		}
		if again := urlHostname(canon); again != canon {
			t.Fatalf("urlHostname is not idempotent: %q -> %q -> %q", host, canon, again)
		}
		labels := strings.Split(canon, ".")
		last := labels[len(labels)-1]
		for _, l := range labels[:len(labels)-1] {
			if !hostLabelRE.MatchString(l) {
				t.Fatalf("label %q of urlHostname output %q does not match hostLabelRE", l, canon)
			}
		}
		if !tldRE.MatchString(last) {
			t.Fatalf("last label %q of urlHostname output %q does not match tldRE", last, canon)
		}
	}

	for authority, want := range map[string]string{
		"Host.Example.com":      "host.example.com", // lowercasing
		"user@Host.Example.com": "host.example.com", // userinfo stripped
	} {
		if got := urlHostname(authority); got != want {
			t.Errorf("urlHostname(%q) = %q, want %q", authority, got, want)
		}
	}
	// urlHostRE captures exactly the authority; the pair is what scanLine feeds.
	m := urlHostRE.FindStringSubmatch("https://Host.Example.com/path")
	if len(m) != 2 || urlHostname(m[1]) != "host.example.com" {
		t.Errorf("urlHostRE/urlHostname round trip = %q, want host.example.com", m)
	}
	m = urlHostRE.FindStringSubmatch("https://user@host.example.com/x")
	if len(m) != 2 || urlHostname(m[1]) != "host.example.com" {
		t.Errorf("urlHostRE/urlHostname round trip with userinfo = %q, want host.example.com", m)
	}

	for _, reject := range []string{"", "localhost", "{host}", "$HOST", "10.0.0.1"} {
		if got := urlHostname(reject); got != "" {
			t.Errorf("urlHostname(%q) = %q, want \"\"", reject, got)
		}
	}
}

func FuzzURLHostname(f *testing.F) {
	for _, seed := range []string{
		"іnstall.example-clі.dev", "user@Example.COM.", "example.com,", "<домен-signal-hunt>",
		"{host}.example", "$HOST.example.com", "localhost", "10.0.0.1", "com（否则",
		"https://Host.Example.com/path", "user@host.example.com", "", "xn--nstall-ovf.dev",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, authority string) {
		host := urlHostname(authority)
		if host == "" {
			return
		}
		if again := urlHostname(host); again != host {
			t.Fatalf("urlHostname is not idempotent: %q -> %q -> %q", authority, host, again)
		}
	})
}

func FuzzLetterScript(f *testing.F) {
	for _, seed := range []string{"a", "1", "-", "і", "Ω", "字", "한", "ア", "ع", "ß", "😀", "\x00"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		for _, r := range s {
			_ = letterScript(r)
		}
	})
}
