package allow

import "testing"

func TestDomainBenign(t *testing.T) {
	benign := []string{
		"html.spec.whatwg.org", "dom.spec.whatwg.org", "url.spec.whatwg.org",
		"whatwg.org", "tidelift.com", "floating-ui.com", "www.typescriptlang.org",
		"typescriptlang.org", "babeljs.io", "jestjs.io", "webpack.js.org",
		"feross.org", "ietf.org", "www.ietf.org", "gitter.im", "hackerone.com",
		"schema.org", "purl.org", "github.com", "gitlab.com", "registry.npmjs.org",
		"datatracker.ietf.org", "tools.ietf.org", "www.rfc-editor.org",
		"tailwindcss.com", "www.tailwindcss.com", "daisyui.com",
		"opencollective.com", "thanks.dev", "paypal.me",
		"unpkg.com", "cdn.jsdelivr.net",
		"HTML.Spec.WHATWG.org", "github.com.", "github.com:443",
		"foo.example", "anything.test",
		"sub.example.com",
	}
	for _, h := range benign {
		if !Domain(h) {
			t.Errorf("Domain(%q) = false, want true (benign)", h)
		}
	}
	malicious := []string{
		"evil.example.io", "evil-c2.com", "exfil.attacker.net", "notwhatwg.org",
		"whatwg.org.evil.com", "tidelift.com.evil.io", "random-package-cdn.ru",
	}
	for _, h := range malicious {
		if Domain(h) {
			t.Errorf("Domain(%q) = true, want false (should be kept)", h)
		}
	}
}

func TestIPBenign(t *testing.T) {
	benign := []string{
		"1.2.3.4", "192.0.2.0", "203.0.113.5", "198.51.100.9", "1.1.1.1",
		"8.8.8.8", "127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.5.5",
		"169.254.1.1", "9.9.9.9", "::1", "fe80::1", "2001:db8::1",
	}
	for _, ip := range benign {
		if !IP(ip) {
			t.Errorf("IP(%q) = false, want true (benign)", ip)
		}
	}
	real := []string{"185.100.157.127", "45.83.122.1", "104.244.42.1", "2606:4700::1111"}
	for _, ip := range real {
		if IP(ip) {
			t.Errorf("IP(%q) = true, want false (real, should be kept)", ip)
		}
	}
}

func TestURLAndBenign(t *testing.T) {
	if !URL("https://html.spec.whatwg.org/multipage/forms.html") {
		t.Error("URL spec link should be benign")
	}
	if URL("https://evil-c2.example.io/beacon") {
		t.Error("non-benign host URL should be kept")
	}
	cases := []struct {
		kind, value string
		want        bool
	}{
		{"domain", "tidelift.com", true},
		{"ipv4", "1.2.3.4", true},
		{"email", "security@github.com", true},
		{"domain", "evil-c2.net", false},
		{"ipv4", "185.100.157.127", false},
		// url / exfil-endpoint are never allowlisted, even on reputable hosts: a
		// discord webhook is a real exfil channel.
		{"url", "https://github.com/x/y", false},
		{"exfil-endpoint", "https://discord.com/api/webhooks/123", false},
		{"install-command", "npm install foo", false}, // unknown kind kept
		{"file-hash", "abc123", false},                // unknown kind kept
	}
	for _, c := range cases {
		if got := Benign(c.kind, c.value); got != c.want {
			t.Errorf("Benign(%q, %q) = %v, want %v", c.kind, c.value, got, c.want)
		}
	}
}
