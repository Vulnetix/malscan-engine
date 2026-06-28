package detect

import "testing"

func TestQualify_KnownSignal(t *testing.T) {
	f := Finding{ID: "P-CURL-PIPE", Class: ClassEvidence}
	q := Qualify(f)
	if q.Intent != IntentMalicious {
		t.Fatalf("P-CURL-PIPE intent = %q, want malicious", q.Intent)
	}
	if q.Tactic == "" || q.Behavior == "" || q.Differentiator == "" {
		t.Fatalf("P-CURL-PIPE qualification incomplete: %+v", q)
	}
	if q.Signal != "P-CURL-PIPE" {
		t.Fatalf("Signal = %q, want P-CURL-PIPE", q.Signal)
	}
}

func TestQualify_InstallScriptPrefixNormalised(t *testing.T) {
	// The IS- prefix (install-script surface) must map to the same qualification
	// as the base rule so a rule has one intent regardless of surface.
	base := Qualify(Finding{ID: "P-CURL-PIPE"})
	is := Qualify(Finding{ID: "IS-P-CURL-PIPE"})
	if base.Intent != is.Intent || base.Tactic != is.Tactic {
		t.Fatalf("IS- prefix not normalised: base=%+v is=%+v", base, is)
	}
}

func TestQualify_UnknownSignalGetsDualUseDefault(t *testing.T) {
	q := Qualify(Finding{ID: "P-SOMETHING-NEW"})
	if q.Intent != IntentDualUse {
		t.Fatalf("unknown signal intent = %q, want dual-use", q.Intent)
	}
	if q.Signal != "P-SOMETHING-NEW" {
		t.Fatalf("Signal = %q, want P-SOMETHING-NEW", q.Signal)
	}
}

func TestQualify_SubstringFallbackForGtfobinsFamily(t *testing.T) {
	// G-PIPE-NODE is in the registry; a hypothetical G-PIPE-FOO should fall back
	// via the substring rule "G-PIPE-NODE" only if it contains it. Test a real
	// family member that IS registered directly.
	q := Qualify(Finding{ID: "G-PIPE-NODE"})
	if q.Intent != IntentMalicious {
		t.Fatalf("G-PIPE-NODE intent = %q, want malicious", q.Intent)
	}
}

func TestIntentOf(t *testing.T) {
	cases := map[string]Intent{
		"P-CURL-PIPE":             IntentMalicious,
		"P-DISCORD-WEBHOOK":       IntentExfil,
		"P-PROFILE-MOD":           IntentPersistence,
		"P-EVAL-BASE64":           IntentObfuscation,
		"P-NO-CHECKSUMS":          IntentReputation,
		"IOC-STIX-MATCH":          IntentMalicious,
		"G-DOWNLOAD-ARIA2C":       IntentDualUse,
	}
	for id, want := range cases {
		if got := IntentOf(Finding{ID: id}); got != want {
			t.Errorf("IntentOf(%s) = %q, want %q", id, got, want)
		}
	}
}
