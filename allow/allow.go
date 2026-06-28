// Package allow is the single source of truth for benign indicators that must
// never be treated as indicators of compromise: reserved/private/placeholder
// IPs, example/test/documentation hosts, and well-known package-registry,
// CDN, standards-body, and developer-docs domains. These are routinely scraped
// out of legitimate package source by the malscan-engine IOC extractor (a legit
// module's README links to html.spec.whatwg.org, its package.json funds via
// tidelift.com, its test fixtures carry 127.0.0.1 / 8.8.8.8) — none of which
// are real exfil indicators.
//
// It is consumed by the producer (ioc.ExtractIOCs, so benign values are never
// minted), by the matcher (iocscan.IndicatorSet, so a still-polluted feed
// cannot flag them at scan time), and by the vdb-manager processors
// (iocfilter + the STIX feed build) so every layer shares one list and cannot
// drift.
//
// The list is deliberately CONSERVATIVE: only values that are unambiguously
// non-indicative are allowlisted, so real C2 hosts and exfil endpoints are
// kept. It has no dependencies beyond the standard library so any package can
// import it.
//
// Updated with findings from the website repo malscan SARIF and recent
// supply-chain malware write-ups (OpenSSF, Socket, Phylum, Aqua, MITRE
// ATT&CK). Entries are grouped by category so a reviewer can reason about why
// a value is non-indicative.
package allow

import (
	"net"
	"strings"
)

// reservedCIDRs are non-global IPv4/IPv6 ranges (RFC1918 private, loopback,
// link-local, CGNAT, documentation TEST-NET-1/2/3, benchmark, multicast,
// reserved). An IP inside any of these is never a real exfil indicator.
var reservedCIDRs = func() []*net.IPNet {
	blocks := []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24",
		"192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
		"224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
		"::1/128", "::/128", "fc00::/7", "fe80::/10", "2001:db8::/32", "ff00::/8",
	}
	out := make([]*net.IPNet, 0, len(blocks))
	for _, b := range blocks {
		if _, n, err := net.ParseCIDR(b); err == nil {
			out = append(out, n)
		}
	}
	return out
}()

// placeholderIPs are globally-routable addresses universally used as examples /
// public resolvers / the literal IP of example.com — never a real indicator.
var placeholderIPs = map[string]bool{
	// Public resolvers
	"1.1.1.1": true, "1.0.0.1": true, "1.1.1.2": true, "1.1.1.3": true, "1.1.1.0": true,
	"1.1.0.0": true, "1.1.1.4": true, "8.8.8.8": true, "8.8.4.4": true, "8.8.0.0": true,
	"8.8.8.0": true, "9.9.9.9": true, "4.4.4.4": true, "4.2.2.2": true, "4.2.2.1": true,
	"114.114.114.114": true, "208.67.222.222": true, "208.67.220.220": true,
	// Common sequence / documentation placeholders
	"2.2.2.2": true, "3.3.3.3": true, "5.5.5.5": true, "6.6.6.6": true, "7.7.7.7": true,
	"93.184.216.34": true, "93.184.215.14": true,
	"1.2.3.4": true, "1.2.3.5": true, "1.2.3.0": true, "1.2.3.1": true, "1.2.3.2": true,
	"1.2.3.3": true, "1.2.3.6": true, "2.3.4.5": true, "3.4.5.6": true, "4.3.2.1": true,
	"5.6.7.8": true, "6.7.8.9": true, "9.10.11.12": true, "9.8.7.6": true,
	"12.34.56.78": true, "1.3.6.1": true, "3.2.1.3": true, "3.2.2.1": true,
	"2.1.1.1": true, "20.20.20.20": true, "10.10.10.10": true,
	"192.0.2.1": true, "198.51.100.1": true, "203.0.113.1": true,
	"192.0.2.2": true, "198.51.100.2": true, "203.0.113.2": true,
}

// exampleTLDs are reserved/special-use suffixes (RFC 2606 / 6761) plus common
// non-routable LAN suffixes. Any host ending in one of these is an example.
var exampleTLDs = []string{
	".example", ".test", ".invalid", ".localhost", ".local", ".lan",
	".internal", ".home", ".corp", ".example.com",
}

// exampleDomains are literal example hosts used in docs and test fixtures.
var exampleDomains = map[string]bool{
	"example.com": true, "example.org": true, "example.net": true, "example.edu": true,
	"test.com": true, "test.test": true, "domain.com": true, "yourdomain.com": true,
	"mydomain.com": true, "foo.com": true, "bar.com": true, "baz.com": true,
	"foo.bar": true, "acme.com": true, "company.com": true, "host.com": true,
	"server.com": true, "email.com": true, "mail.com": true, "sample.com": true,
	"site.com": true, "url.com": true,
}

// genericServiceHosts are legit infrastructure / registry / CDN / standards /
// docs hosts that are never IOCs on their own.
//
// Categorisation reflects why the host is non-indicative:
//   - source forges and issue trackers (github.com, gitlab.com, …)
//   - package registries and CDNs (npmjs.org, jsdelivr, unpkg, …)
//   - developer docs / project homepages (typescriptlang.org, react.dev, …)
//   - standards bodies / specifications (w3.org, ietf.org, …)
//   - package-funding / donation platforms (tidelift, open collective, …)
var genericServiceHosts = map[string]bool{
	// ── Source forges / collaboration ────────────────────────────────────────
	"github.com": true, "raw.githubusercontent.com": true, "api.github.com": true,
	"objects.githubusercontent.com": true, "gist.github.com": true, "codeload.github.com": true,
	"gitlab.com": true, "invent.kde.org": true, "salsa.debian.org": true,
	"bitbucket.org": true, "sourceforge.net": true, "git.savannah.gnu.org": true,
	"gitter.im": true, "matrix.to": true,
	"stackoverflow.com": true, "stackexchange.com": true,
	"wikipedia.org": true, "www.wikipedia.org": true,
	"hackerone.com": true, "bugcrowd.com": true,
	"launchpad.net": true, "tuleap.org": true,

	// ── Package registries ───────────────────────────────────────────────────
	"registry.npmjs.org": true, "npmjs.com": true, "www.npmjs.com": true,
	"npmjs.org": true, "registry.yarnpkg.com": true, "yarnpkg.com": true,
	"pnpm.io": true,
	"pypi.org": true, "test.pypi.org": true, "files.pythonhosted.org": true,
	"crates.io": true, "static.crates.io": true,
	"rubygems.org": true,
	"packagist.org": true, "repo.packagist.org": true,
	"golang.org": true, "pkg.go.dev": true, "proxy.golang.org": true, "sum.golang.org": true,
	"go.dev": true, "gopkg.in": true, "goproxy.io": true,
	"maven.apache.org": true, "repo.maven.apache.org": true, "repo1.maven.org": true,
	"nuget.org": true, "www.nuget.org": true, "api.nuget.org": true,
	"pub.dev": true, "hex.pm": true, "opam.ocaml.org": true,
	"chocolatey.org": true, "community.chocolatey.org": true,

	// ── Vendors / clouds / resolvers ─────────────────────────────────────────
	"google.com": true, "www.google.com": true, "googleapis.com": true,
	"fonts.googleapis.com": true, "ajax.googleapis.com": true,
	"cloudflare.com": true, "cdn.cloudflare.net": true,
	"discord.com": true, "discordapp.com": true,
	"microsoft.com": true, "www.microsoft.com": true,
	"mozilla.org": true, "www.mozilla.org": true,
	"telegram.org": true, "core.telegram.org": true,
	"localhost": true,

	// ── Standards bodies / specifications / schemas ──────────────────────────
	"www.w3.org": true, "w3.org": true, "www.apache.org": true, "apache.org": true,
	"opensource.org": true, "creativecommons.org": true, "spdx.org": true,
	"json-schema.org": true, "xmlns.jcp.org": true, "java.sun.com": true,
	"schemas.android.com": true, "schema.org": true, "purl.org": true,
	"whatwg.org": true, "www.whatwg.org": true, "html.spec.whatwg.org": true,
	"dom.spec.whatwg.org": true, "url.spec.whatwg.org": true, "encoding.spec.whatwg.org": true,
	"ietf.org": true, "www.ietf.org": true, "datatracker.ietf.org": true,
	"tools.ietf.org": true, "rfc-editor.org": true, "www.rfc-editor.org": true,
	"unicode.org": true, "www.unicode.org": true, "ecma-international.org": true,

	// ── JS / CSS / font CDNs and common module hosts ─────────────────────────
	"unpkg.com": true, "cdn.jsdelivr.net": true, "jsdelivr.net": true,
	"fastly.jsdelivr.net": true, "cdnjs.cloudflare.com": true,
	"esm.sh": true, "skypack.dev": true, "ga.jspm.io": true,
	"rawgit.com": true, "gitcdn.xyz": true,

	// ── Well-known developer docs / project homepages (docs/funding/badge) ───
	"tidelift.com": true, "floating-ui.com": true, "typescriptlang.org": true,
	"www.typescriptlang.org": true, "babeljs.io": true, "jestjs.io": true,
	"webpack.js.org": true, "feross.org": true, "eslint.org": true, "prettier.io": true,
	"reactjs.org": true, "react.dev": true, "vuejs.org": true, "rollupjs.org": true,
	"vitejs.dev": true, "tailwindcss.com": true, "www.tailwindcss.com": true,
	"daisyui.com": true,
	"readthedocs.io": true, "readthedocs.org": true,
	"docs.rs": true, "js.org": true, "deno.land": true, "nuxt.com": true,
	"vueuse.org": true, "vueuse.com": true,
	"docs.python.org": true, "python.org": true, "nodejs.org": true,
	"docs.npmjs.com": true, "rust-lang.org": true, "www.rust-lang.org": true,

	// ── Funding / sponsorship platforms ──────────────────────────────────────
	"opencollective.com": true, "thanks.dev": true,
	"liberapay.com": true, "patreon.com": true, "www.patreon.com": true,
	"ko-fi.com": true, "www.ko-fi.com": true, "buymeacoffee.com": true,
	"paypal.com": true, "www.paypal.com": true, "paypal.me": true,
	"flattr.com": true, "issuehunt.io": true, "polar.sh": true,
}

// benignHostSuffixes are suffixes whose every subdomain is benign and operator-
// controlled (not user-generated). Only narrow, unambiguous suffixes are listed.
var benignHostSuffixes = []string{
	".spec.whatwg.org",
	".docs.npmjs.com",
}

// Domain reports whether host is a benign (non-IOC) domain. The comparison is
// case-insensitive and tolerant of a trailing root dot and a :port suffix.
func Domain(host string) bool {
	h := normHost(host)
	if h == "" || exampleDomains[h] {
		return true
	}
	if genericServiceHosts[h] {
		return true
	}
	for d := range exampleDomains {
		if h == d || strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	for d := range genericServiceHosts {
		if h == d || strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	for _, t := range exampleTLDs {
		if strings.HasSuffix(h, t) {
			return true
		}
	}
	for _, s := range benignHostSuffixes {
		if strings.HasSuffix(h, s) {
			return true
		}
	}
	return false
}

// IP reports whether ip is a reserved/private/placeholder address (never a real
// exfil indicator).
func IP(ip string) bool {
	v := strings.TrimSpace(ip)
	if placeholderIPs[v] {
		return true
	}
	parsed := net.ParseIP(v)
	if parsed == nil {
		return false
	}
	for _, n := range reservedCIDRs {
		if n.Contains(parsed) {
			return true
		}
	}
	// All-equal-octet IPv4 (1.1.1.1, 9.9.9.9, 123.123.123.123) are placeholders.
	if v4 := parsed.To4(); v4 != nil && v4[0] == v4[1] && v4[1] == v4[2] && v4[2] == v4[3] {
		return true
	}
	return false
}

// URL reports whether u points at a benign host.
//
// NOTE on path-sensitive services: a full URL such as
// `discord.com/api/webhooks/<token>` or `api.telegram.org/bot<token>` is an
// IOC in its own right and is represented in the feed as a `url` (not
// `domain`) indicator. URL() only looks at the host, so those complete URLs
// remain matchable. The bare host (`discord.com` without a webhook path) is
// still allowlisted here because many packages legitimately link to discord.com
// or telegram.org documentation/announcements.
func URL(u string) bool {
	return Domain(hostOf(u))
}

// Benign reports whether a (kind, value) indicator is benign and should be
// dropped. kind is matched against the IOC/indicator type open set
// (domain | ipv4 | ipv6 | ip | hostname | fqdn | email).
//
// Deliberately NOT allowlisted:
//   - url — a feed `url` indicator is a SPECIFIC known-bad URL; keep them all
//     (the bare-domain FPs are handled by the `domain` branch, and the matcher
//     looks up a URL's host as a separate domain indicator anyway).
//   - exfil-endpoint / c2 — already classified malicious by the producer; an
//     exfil channel on an otherwise-reputable host (e.g. discord.com/api/webhooks)
//     must never be dropped just because the bare host is reputable.
//   - wallet / file-hash / install-command — these have no host component.
//
// Unknown kinds are conservatively kept (return false).
func Benign(kind, value string) bool {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "ipv4", "ipv6", "ip":
		return IP(value)
	case "domain", "hostname", "fqdn":
		return Domain(value)
	case "email":
		return Domain(hostOf(value))
	}
	return false
}

// normHost lowercases a bare host and strips a trailing dot and a :port suffix.
func normHost(host string) string {
	h := strings.TrimSuffix(strings.TrimSpace(strings.ToLower(host)), ".")
	if h == "" {
		return ""
	}
	if strings.HasPrefix(h, "[") { // ipv6 literal [..]:port
		if j := strings.Index(h, "]"); j > 0 {
			return h[1:j]
		}
	}
	// Strip :port only when the remainder before ':' is not itself part of an
	// (unbracketed) IPv6 literal — bare IPv6 has multiple colons.
	if strings.Count(h, ":") == 1 {
		h = h[:strings.Index(h, ":")]
	}
	return strings.TrimSuffix(h, ".")
}

// hostOf extracts the host from a URL, email, or bare host string.
func hostOf(value string) string {
	v := strings.ToLower(strings.TrimSpace(value))
	if i := strings.Index(v, "://"); i >= 0 {
		v = v[i+3:]
	}
	if at := strings.LastIndex(v, "@"); at >= 0 { // email or user:pass@host
		v = v[at+1:]
	}
	for _, sep := range []string{"/", "?", "#"} {
		if i := strings.Index(v, sep); i >= 0 {
			v = v[:i]
		}
	}
	return normHost(v)
}
