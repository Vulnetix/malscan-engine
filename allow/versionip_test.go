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

// X.509 object identifiers parse as dotted quads and are everywhere in crypto
// code. malscan-stix published 2.5.29.35 (authorityKeyIdentifier) typed as IPV4
// into the PUBLIC STIX feed. The octets<=31 rule caught only part of the arc —
// 2.5.29.14 and 2.5.29.17 were dropped while 2.5.29.35 and 2.5.29.255 were not,
// splitting one namespace arbitrarily.
func TestVersionLikeIPRejectsX509OIDs(t *testing.T) {
	for _, v := range []string{
		"2.5.29.35",  // authorityKeyIdentifier — the one that was published
		"2.5.29.14",  // subjectKeyIdentifier
		"2.5.29.17",  // subjectAltName
		"2.5.29.19",  // basicConstraints
		"2.5.29.255", // above the old octet ceiling
		"2.5.4.3",    // commonName
		"2.5.4.10",   // organizationName
	} {
		if !VersionLikeIP(v) {
			t.Errorf("VersionLikeIP(%q) = false, want true — this OID publishes as a malicious IP", v)
		}
	}
}

// The arc prefixes must not swallow neighbouring real addresses.
func TestVersionLikeIPKeepsAddressesNearTheOIDArcs(t *testing.T) {
	for _, v := range []string{"2.5.30.35", "2.6.29.35", "3.5.29.35", "2.55.29.35"} {
		if VersionLikeIP(v) {
			t.Errorf("VersionLikeIP(%q) = true, want false — outside the 2.5.29/2.5.4 arcs", v)
		}
	}
}
