package allow

import "testing"

// Values from withdrawn GCVE malware audit lines (2026-10-26) that matched the embedded badnet
// feed: public resolvers, root and gTLD servers, AliDNS's anycast block, DNS CHAOS query
// names, vendor download hosts and LLM provider endpoints.
func TestAuditDNSInfraAndVendorHostsAreBenign(t *testing.T) {
	for _, ip := range []string{
		"8.26.56.26", "8.20.247.20", "156.154.70.1", "114.114.115.115", "77.88.8.88",
		"45.90.28.0", "94.140.14.140", "195.46.39.40", "101.102.103.104", "80.67.169.12",
		"198.41.0.4", "170.247.170.2", "193.0.14.129", "202.12.27.33", // root servers
		"192.5.6.30", "192.48.79.30", // gTLD servers
		"223.5.5.0", "223.5.5.77", "223.6.6.6", // AliDNS anycast blocks
	} {
		if !Benign("ipv4", ip) {
			t.Errorf("Benign(ipv4, %q) = false — a public DNS service address", ip)
		}
	}
	for _, h := range []string{
		"version.bind", "hostname.bind", "id.server", "version.server", "authors.bind",
		"api.adoptium.net", "dl.google.com", "coralogix.io", "ingress.eu2.coralogix.io",
		"dashscope.aliyuncs.com", "platform.claude.com", "api.githubcopilot.com",
		"api.anthropic.com", "api.openai.com", "api.deepseek.com", "generativelanguage.googleapis.com",
	} {
		if !Benign("domain", h) {
			t.Errorf("Benign(domain, %q) = false", h)
		}
	}
}

// The additions are single addresses or two /24s, not a provider's whole range, and none of
// them is a payload-capable shared platform.
func TestAuditDNSInfraStaysNarrow(t *testing.T) {
	for _, ip := range []string{
		"8.26.56.27", "156.154.70.9", "45.90.29.17", "198.41.0.5", "223.5.6.1",
		"206.189.81.181", "185.220.101.4", // verified malware gate / Tor exit: never allowed
	} {
		if Benign("ipv4", ip) {
			t.Errorf("Benign(ipv4, %q) = true — must stay matchable", ip)
		}
	}
	for _, h := range []string{
		"claude.ai", "evil.bind", "google.com.evil.example2", "adoptium.net.evil.io",
		"raw.githubusercontent.com.evil.io", "workers.dev", "x.trycloudflare.com",
		"pastebin.com", "webhook.site",
	} {
		if Benign("domain", h) {
			t.Errorf("Benign(domain, %q) = true — must stay matchable", h)
		}
	}
}

func TestSharedHost(t *testing.T) {
	for _, v := range []string{"www.dropbox.com", "dropbox.com", "f005.backblazeb2.com", "ntfy.sh",
		"76.76.21.21", "140.82.121.4", "185.199.108.153", "185.199.111.133"} {
		if !SharedHost(v) {
			t.Errorf("SharedHost(%q) = false", v)
		}
		if Benign("domain", v) || Benign("ipv4", v) {
			t.Errorf("%q must not be benign: a shared platform can still carry a payload", v)
		}
	}
	for _, v := range []string{"evilbucket.s3.us-west-004.backblazeb2.com", "fabc.backblazeb2.com",
		"dropbox.com.evil.io", "76.76.21.22", "206.189.81.181", "x.vercel.app", "rocket-sense.duckdns.org"} {
		if SharedHost(v) {
			t.Errorf("SharedHost(%q) = true — names a tenant or an unrelated host", v)
		}
	}
}
