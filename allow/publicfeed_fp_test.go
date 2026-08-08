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

// After the first false-positive purge, the surviving critical-severity
// MalwareHost domains still included six documentation hosts, all published in a
// PUBLIC STIX feed. Enumerating vendors one at a time keeps losing that race, so
// the leftmost label is the signal.
func TestDocSubdomainsAreBenign(t *testing.T) {
	for _, h := range []string{
		"docs.n8n.io", "docs.openstack.org", "docs.exodus.com",
		"docs.automagik.dev", "docs.embedder.com", "docs.rongcloud.cn",
		"doc.rust-lang.org", "documentation.suse.com",
		"readthedocs.example.org", "apidocs.example.com",
	} {
		if !Benign("domain", h) {
			t.Errorf("Benign(domain, %q) = false — a documentation host publishes as a malicious indicator", h)
		}
	}
}

// The rule must need a real subdomain: a two-label host called "docs.<tld>" is a
// registrable name, not a documentation subdomain, and must not be allowed.
func TestDocRuleRequiresASubdomain(t *testing.T) {
	for _, h := range []string{"docs.io", "doc.ai", "documentation.co"} {
		if Benign("domain", h) {
			t.Errorf("Benign(domain, %q) = true — a two-label host is registrable, not a docs subdomain", h)
		}
	}
	// A non-docs subdomain on an unknown domain is still an indicator.
	for _, h := range []string{"cdn.evil-drop.top", "c2.attacker.net", "loginbp.ggpolarbear.com"} {
		if Benign("domain", h) {
			t.Errorf("Benign(domain, %q) = true — genuine indicators must survive", h)
		}
	}
}

// Survivors added explicitly, each published at critical before this change.
func TestPurgeSurvivorsAllowlisted(t *testing.T) {
	for _, h := range []string{
		"alpinejs.dev", "contributor-covenant.org",
		"chatapi.viber.com", "api.devnet.solana.com", "api.testnet.solana.com",
	} {
		if !Benign("domain", h) {
			t.Errorf("Benign(domain, %q) = false", h)
		}
	}
}
