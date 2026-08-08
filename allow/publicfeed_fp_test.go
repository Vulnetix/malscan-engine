package allow

import "testing"

// These three were published at severity critical into the PUBLIC malscan-stix
// STIX feed, so a false positive here is visible outside Vulnetix. Confirmed in
// both the database and the published feed before this fix.
func TestPublicFeedFalsePositivesAreBenign(t *testing.T) {
	// "@click.group" is Click's command decorator, not a hostname.
	if !CodeTokenDomain("click.group") {
		t.Error(`CodeTokenDomain("click.group") = false — the @click.group decorator publishes as a malicious domain`)
	}
	// uv / ruff documentation.
	if !Benign("domain", "docs.astral.sh") {
		t.Error(`Benign("domain", "docs.astral.sh") = false — uv's docs site publishes as malicious`)
	}
	// Already allowlisted before this change; asserted so it cannot regress.
	if !Benign("domain", "huggingface.co") {
		t.Error(`Benign("domain", "huggingface.co") = false`)
	}
}

// The additions must not blanket-allow the gTLDs or vendors involved.
func TestPublicFeedFixesStayNarrow(t *testing.T) {
	// A brand SLD on a code-colliding gTLD is still an indicator.
	for _, h := range []string{"evilc2.group", "malware-drop.group", "mybrand.top"} {
		if CodeTokenDomain(h) {
			t.Errorf("CodeTokenDomain(%q) = true — a real indicator would be suppressed", h)
		}
	}
	// Unrelated .sh hosts are not allowlisted by adding astral.sh.
	for _, h := range []string{"evil.sh", "c2.attacker.sh"} {
		if Benign("domain", h) {
			t.Errorf("Benign(domain, %q) = true — .sh must not be blanket-allowed", h)
		}
	}
}
