package detect

import "testing"

func findingByID(fs []Finding, id string) *Finding {
	for i := range fs {
		if fs[i].ID == id {
			return &fs[i]
		}
	}
	return nil
}

func TestHomographMixedScriptIsEvidence(t *testing.T) {
	// The aur-general example: Cyrillic і (U+0456) swapped into a Latin hostname.
	ctx := &PackageContext{PkgbuildContent: "source=(\"https://іnstall.example-clі.dev/payload.sh\")"}
	fs := analyzeHomograph(ctx)
	f := findingByID(fs, "P-HOMOGRAPH-MIXED-SCRIPT")
	if f == nil {
		t.Fatalf("expected mixed-script homograph finding, got %+v", fs)
	}
	if f.Class != ClassEvidence {
		t.Errorf("mixed-script should be evidence, got %s", f.Class)
	}
	if !IsMalicious(fs) {
		t.Error("a mixed-script source host should mint on its own")
	}
}

func TestHomographPunycodeIsContextOnly(t *testing.T) {
	ctx := &PackageContext{PkgbuildContent: "source=(\"http://xn--nstall-ovf.xn--example-cl-62i.dev/x\")"}
	fs := analyzeHomograph(ctx)
	f := findingByID(fs, "P-IDN-PUNYCODE-HOST")
	if f == nil {
		t.Fatalf("expected punycode finding, got %+v", fs)
	}
	if f.Class != ClassContext {
		t.Errorf("punycode should be context (legit IDN possible), got %s", f.Class)
	}
	if IsMalicious(fs) {
		t.Error("a punycode host alone must NOT mint")
	}
}

func TestHomographCleanURLsNoFinding(t *testing.T) {
	ctx := &PackageContext{
		PkgbuildContent: "source=(\"https://install.example-cli.dev/x.tgz\" \"git+https://github.com/owner/repo.git\")",
		Meta:            &PackageMeta{URL: "https://example.org", Source: []string{"https://files.pythonhosted.org/x.tar.gz"}},
	}
	if fs := analyzeHomograph(ctx); len(fs) != 0 {
		t.Errorf("clean ASCII URLs should produce no homograph finding, got %+v", fs)
	}
}
