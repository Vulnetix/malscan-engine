package ioc

import "testing"

// TestExtractIOCsDropsBenignKeepsReal pins the producer-side allowlist: legit
// spec/docs/registry domains and reserved/placeholder IPs scraped from package
// source must never become IOCs (this is what was polluting the STIX feed), while
// genuine exfil endpoints and real IPs are still extracted.
func TestExtractIOCsDropsBenignKeepsReal(t *testing.T) {
	repo := &RepoData{
		PkgbuildContent: `
# legit references that must NOT become IOCs:
# see https://html.spec.whatwg.org/multipage/forms.html
# funding: https://tidelift.com/funding/github/npm/foo
# docs: https://www.typescriptlang.org/docs
# homepage http://github.com/x/y
# test fixtures: 1.2.3.4, 192.0.2.10, 8.8.8.8, 127.0.0.1
`,
		InstallScripts: `
curl -s https://discord.com/api/webhooks/123/abc
ping 185.100.157.127
`,
	}
	got := ExtractIOCs(repo)

	benign := []string{
		"html.spec.whatwg.org", "tidelift.com", "www.typescriptlang.org",
		"github.com", "1.2.3.4", "192.0.2.10", "8.8.8.8",
		"https://html.spec.whatwg.org/multipage/forms.html",
	}
	for _, b := range got {
		for _, bad := range benign {
			if b.Value == bad {
				t.Errorf("benign indicator %q (%s) must not be extracted as an IOC", b.Value, b.Type)
			}
		}
	}

	// The discord webhook (exfil-endpoint) and the real IP must survive.
	var sawExfil, sawIP bool
	for _, b := range got {
		if b.Type == "exfil-endpoint" && b.Value == "https://discord.com/api/webhooks/123/abc" {
			sawExfil = true
		}
		if b.Type == "ipv4" && b.Value == "185.100.157.127" {
			sawIP = true
		}
	}
	if !sawExfil {
		t.Errorf("discord webhook exfil-endpoint must be kept; got %v", got)
	}
	if !sawIP {
		t.Errorf("real IP 185.100.157.127 must be kept; got %v", got)
	}
}
