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

// suppressPackagingIdiom reports whether rule id's match on line is a packaging idiom.
func suppressPackagingIdiom(id, line string) bool {
	switch id {
	case "P-SUID-BIT", "P-KERNEL-MODULE-WRITE", "P-UDEV-RULE", "P-PACMAN-HOOK":
		return stagingRootRE.MatchString(line)
	case "P-EVAL-VAR":
		return splitPackageEvalRE.MatchString(line)
	case "P-PYTHON-INLINE":
		return pythonQueryRE.MatchString(line) && !pythonHostileRE.MatchString(line)
	case "P-INSTALL-PERSISTENCE":
		return echoedMessageRE.MatchString(line)
	}
	return false
}
