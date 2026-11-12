package allow

import (
	"math/rand/v2"
	"strings"
	"testing"
)

// hostAlphabet is the ASCII material hosts are made of: letters (so case
// folding has something to do), digits, and the punctuation normHost and
// hostOf special-case (dots, colons, brackets, ports, userinfo, schemes,
// paths and stray whitespace).
const hostAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.:[]-@/?#%_~ "

// randomHostString returns a random string over hostAlphabet, including the
// empty string.
func randomHostString(r *rand.Rand) string {
	n := r.IntN(48)
	b := make([]byte, n)
	for i := range b {
		b[i] = hostAlphabet[r.IntN(len(hostAlphabet))]
	}
	return string(b)
}

// isASCII reports whether every byte of s is < 0x80. The case-invariance
// invariants only hold for ASCII hosts: Go's non-Turkic case mapping makes
// them false for inputs like "ı" or "ſ", which are not valid host material
// (IDNs are punycode).
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func TestNormHostProperties(t *testing.T) {
	// Exact examples from the invariants: trailing dot, :port, IPv6 forms.
	cases := []struct{ in, want string }{
		{"Example.COM.", "example.com"},
		{"example.com:443", "example.com"},
		{"::1", "::1"},
		{"[::1]:80", "::1"},
		{"", ""},
		{"github.com", "github.com"},
		{"Host.COM.:443", "host.com"},
		{"  github.com:443  ", "github.com"},
		{"[fe80::1]:8080", "fe80::1"},
	}
	for _, c := range cases {
		if got := normHost(c.in); got != c.want {
			t.Errorf("normHost(%q) = %q, want %q", c.in, got, c.want)
		}
	}

	r := rand.New(rand.NewPCG(0xae7aa9, 0xae7aa9))
	for i := 0; i < 5000; i++ {
		h := randomHostString(r)
		got := normHost(h)
		if again := normHost(got); again != got {
			t.Errorf("normHost(%q) = %q, but normHost(%q) = %q: not idempotent", h, got, got, again)
		}
		if u := normHost(strings.ToUpper(h)); u != got {
			t.Errorf("normHost(%q) = %q, but normHost(strings.ToUpper(%q)) = %q", h, got, h, u)
		}
		if l := normHost(strings.ToLower(h)); l != got {
			t.Errorf("normHost(%q) = %q, but normHost(strings.ToLower(%q)) = %q", h, got, h, l)
		}
		// A bare host with no scheme, userinfo or path is what hostOf yields.
		if !strings.Contains(h, "://") && !strings.ContainsAny(h, "@/?#") {
			if ho := hostOf(h); ho != got {
				t.Errorf("hostOf(%q) = %q, normHost(%q) = %q: bare-host disagreement", h, ho, h, got)
			}
		}
	}

	// Scheme-insensitive and userinfo-stripping examples for hostOf.
	hostCases := []struct{ in, want string }{
		{"https://Host.COM/p", "host.com"},
		{"HTTP://host.com/P", "host.com"},
		{"user:pw@host.com", "host.com"},
		{"security@github.com", "github.com"},
		{"https://user:pw@Host.COM:8443/path?q=1#frag", "host.com"},
		{"example.com:443", "example.com"},
		{"::1", "::1"},
		{"[::1]:80", "::1"},
		{"  github.com  ", "github.com"},
	}
	for _, c := range hostCases {
		if got := hostOf(c.in); got != c.want {
			t.Errorf("hostOf(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func FuzzNormHost(f *testing.F) {
	for _, seed := range []string{
		"Example.COM.", "example.com:443", "::1", "[::1]:80", "Host.COM",
		"  github.com:443  ", "a.:80", ".", "", "EXAMPLE.COM..", ". ..", ". ",
		"[fe80::1]:8080", "user@Host.com", "https://Host.COM/p?x=1#f",
		"a/b", "host.com.",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, h string) {
		got := normHost(h)
		if again := normHost(got); again != got {
			t.Fatalf("normHost(%q) = %q, but normHost(%q) = %q: not idempotent", h, got, got, again)
		}
		if !isASCII(h) {
			return
		}
		if u := normHost(strings.ToUpper(h)); u != got {
			t.Fatalf("normHost(%q) = %q, but normHost(strings.ToUpper(%q)) = %q", h, got, h, u)
		}
		if l := normHost(strings.ToLower(h)); l != got {
			t.Fatalf("normHost(%q) = %q, but normHost(strings.ToLower(%q)) = %q", h, got, h, l)
		}
	})
}

func FuzzHostOf(f *testing.F) {
	for _, seed := range []string{
		"https://Host.COM/p", "HTTP://host.com/P", "user:pw@host.com",
		"security@github.com", "example.com:443", "::1", "[::1]:80",
		"Host.COM", "a@b@c.com",
		"https://user:pw@Host.COM:8443/path?q=1#frag", "", "  github.com  ",
		"a/b", "mailto:user@example.com",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, v string) {
		got := hostOf(v)
		if again := hostOf(got); again != got {
			t.Fatalf("hostOf(%q) = %q, but hostOf(%q) = %q: not idempotent", v, got, got, again)
		}
		if !strings.Contains(v, "://") && !strings.ContainsAny(v, "@/?#") {
			if want := normHost(v); got != want {
				t.Fatalf("hostOf(%q) = %q, normHost(%q) = %q: bare-host disagreement", v, got, v, want)
			}
		}
	})
}
