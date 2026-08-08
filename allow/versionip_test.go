package allow

import "testing"

// A pubdev mint (GCVE-110-PUB-2026-000236) was created because the STIX
// indicator "Malicious IP address 120.0.0.0" matched the text
// "Chrome/120.0.0.0 Safari/537.36" — a user-agent version, not a network
// indicator. The octets<=31 rule could not catch it: Chrome major versions are
// far past 31. A dotted quad whose last three octets are zero is a /8 network
// address and never a host worth naming as an indicator.
func TestVersionLikeIPRejectsBrowserVersions(t *testing.T) {
	for _, v := range []string{
		"120.0.0.0", // Chrome
		"131.0.0.0",
		"140.0.0.0",
		"99.0.0.0",
		"1.0.0.0",
	} {
		if !VersionLikeIP(v) {
			t.Errorf("VersionLikeIP(%q) = false, want true — this shape mints malware off a user-agent string", v)
		}
	}
}

// Real host addresses must still be treated as indicators, including ones that
// merely start with a large octet.
func TestVersionLikeIPKeepsRealHostIPs(t *testing.T) {
	for _, v := range []string{
		"120.0.0.1",
		"185.199.108.153", // github pages
		"203.0.113.42",
		"120.0.1.0",
		"120.1.0.0",
	} {
		if VersionLikeIP(v) {
			t.Errorf("VersionLikeIP(%q) = true, want false — a genuine indicator would be dropped", v)
		}
	}
}

// The pre-existing octets<=31 behaviour must be preserved.
func TestVersionLikeIPKeepsCoordinateShapes(t *testing.T) {
	// 8.8.8.8 and 1.1.1.1 belong here, not with the host IPs: they are
	// coordinate-shaped, and the pre-existing octets<=31 rule drops them
	// deliberately. Both are public resolvers that no feed should be minting
	// malware on anyway, so the trade is sound.
	for _, v := range []string{"1.2.3.4", "10.11.12.13", "31.31.31.31", "8.8.8.8", "1.1.1.1"} {
		if !VersionLikeIP(v) {
			t.Errorf("VersionLikeIP(%q) = false, want true", v)
		}
	}
	for _, v := range []string{"", "not-an-ip", "1.2.3", "::1"} {
		if VersionLikeIP(v) {
			t.Errorf("VersionLikeIP(%q) = true, want false", v)
		}
	}
}
