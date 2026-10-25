package detect

import "testing"

func goFinding(line, id string) (Finding, bool) {
	for _, f := range Detect(&PackageContext{Name: "m", Ecosystem: "go", PkgbuildContent: line}) {
		if f.ID == id {
			return f, true
		}
	}
	return Finding{}, false
}

// GO-EXEC-SHELL reports a shell fed a built command; the author's own literal command is not a
// weakness. Lines from the 2026-10-25 audit.
func TestGoExecShellNeedsABuiltCommand(t *testing.T) {
	for _, line := range []string{
		`cmd := exec.Command("/bin/sh", "-c", "dd if=/dev/zero bs=1k count=1000 of=/dev/stderr; echo hello")`,
		`cmd := exec.Command("bash", "-c")`,
	} {
		if _, ok := goFinding(line, "GO-EXEC-SHELL"); ok {
			t.Errorf("fired on %q", line)
		}
	}
	for _, line := range []string{
		`cmd := exec.Command("sh", "-c", line)`,
		`c := exec.Command("bash", "-c", fmt.Sprintf("wget -q -O- %s | bash", mainURL))`,
		`out, _ := exec.Command("bash", "-c", "docker inspect "+*container+" | jq .").CombinedOutput()`,
	} {
		if f, ok := goFinding(line, "GO-EXEC-SHELL"); !ok || f.Class != ClassWeakness {
			t.Errorf("want a weakness on %q, got %+v", line, f)
		}
	}
}

// syscall.Exec takes an argv: no shell parses it, so it is context, not a CWE-78 weakness.
func TestGoSyscallExecIsContext(t *testing.T) {
	f, ok := goFinding(`syscall.Exec(path, argv, os.Environ())`, "GO-SYSCALL-EXEC")
	if !ok || f.Class != ClassContext {
		t.Errorf("want context, got %+v (found %v)", f, ok)
	}
}
