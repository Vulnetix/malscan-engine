package allow

import "testing"

// A pubdev mint was created from "Malicious domain commit.author.email". That is
// a git config key, matched as a domain only because .email is a registrable
// gTLD. CodeTokenDomain exists to catch exactly this shape and did not.
func TestCodeTokenDomainCatchesConfigKeys(t *testing.T) {
	for _, h := range []string{
		"commit.author.email",
		"package.maintainer.email",
		"git.user.email",
		"pkg.owner.email",
		"repo.committer.email",
		"msg.sender.email",
		"form.contact.email",
	} {
		if !CodeTokenDomain(h) {
			t.Errorf("CodeTokenDomain(%q) = false, want true — this config key mints malware as a domain", h)
		}
	}
}

// Real hosts must keep matching, including on gTLDs deliberately left out of the
// code-colliding list because genuine services live there.
func TestCodeTokenDomainKeepsRealHosts(t *testing.T) {
	for _, h := range []string{
		"api.anthropic.com",
		"registry.npmjs.org",
		"cgr.dev",
		"myapp.vercel.app",
		"evilc2.top",  // a real malicious host on a code-colliding gTLD:
		"mybrand.xyz", // the SLD is not an identifier, so it still matches
		"malware-drop.group",
		"mail.protonmail.email", // .email host whose SLD is a brand, not an identifier
	} {
		if CodeTokenDomain(h) {
			t.Errorf("CodeTokenDomain(%q) = true, want false — a genuine indicator would be suppressed", h)
		}
	}
}
