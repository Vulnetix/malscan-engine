package detect

import (
	"strings"
	"testing"
)

// Metadata and diff detectors, from the 2026-10-25 read of the 814 still-malicious AUR set-A mints.
// The replay harness cannot reproduce these (they need the url=, the prior PKGBUILD or the git log),
// so each fix is pinned here with the audited shape and the real hostile shape beside it.

func classOf(fs []Finding, id string) (Class, bool) {
	for _, f := range fs {
		if f.ID == id {
			return f.Class, true
		}
	}
	return "", false
}

func binPkgbuild(sources ...string) string {
	return "pkgname=foo-bin\npkgver=1.0\nsource=(" + strings.Join(sources, "\n        ") + ")\nsha256sums=('SKIP')\n"
}

func TestRegistrableDomain(t *testing.T) {
	for host, want := range map[string]string{
		"beeper-desktop.download.beeper.com": "beeper.com",
		"download.beeper.com":                "beeper.com",
		"pkg.sober-dev.app":                  "sober-dev.app",
		"www.example.co.uk":                  "example.co.uk",
		"alice.github.io":                    "alice.github.io",
		"bucket.s3.amazonaws.com":            "bucket.s3.amazonaws.com",
		"s3-eu-west-1.amazonaws.com":         "s3-eu-west-1.amazonaws.com",
		"gitlab.mpi-magdeburg.mpg.de":        "mpg.de",
		"162.19.230.104":                     "162.19.230.104",
		"github.com":                         "github.com",
	} {
		if got := registrableDomain(host); got != want {
			t.Errorf("registrableDomain(%q) = %q, want %q", host, got, want)
		}
	}
}

func TestBinDomainMismatchAuditFalsePositives(t *testing.T) {
	for _, tc := range []struct{ url, src string }{
		// same registrable domain
		{"https://www.beeper.com", "https://beeper-desktop.download.beeper.com/builds/Beeper-4.3.209-x86_64.AppImage"},
		// raw.githubusercontent.com of the upstream's own repo
		{"https://github.com/usestrix/strix", "https://raw.githubusercontent.com/usestrix/strix/v1.0/LICENSE.txt"},
		{"https://github.com/usestrix/strix", "https://raw.githubusercontent.com/usestrix/strix/v1.0/strix.desktop"},
		// the GitHub org the url= domain names
		{"https://app.lizardbyte.dev", "https://github.com/LizardByte/Sunshine/blob/master/packaging/linux/dev.lizardbyte.app.Sunshine.desktop"},
		// a licence text, an EULA, a checksum list
		{"https://example.org/app", "https://www.gnu.org/licenses/gpl-3.0.txt"},
		{"https://cloud-fs.example", "https://raw.githubusercontent.com/cloud-fs/cloud-fs.github.io/gh-pages/eula.html"},
		{"https://sober.vinegarhq.org", "https://pkg.sober-dev.app/ce/SHA256SUMS"},
		// an icon
		{"https://example.org/app", "https://upload.wikimedia.org/wikipedia/commons/a/ab/Logo.svg"},
		// the npm registry and PyPI
		{"https://example.org/cli", "https://registry.npmjs.org/@acme/cli/-/cli-1.2.3.tgz"},
		{"https://example.org/tool", "https://files.pythonhosted.org/packages/py3/t/tool/tool-1.0-py3-none-any.whl"},
		// a local file
		{"https://example.org/receiver", "file://ZCentral_RB_22.1_Linux_Receiver_M39127-009.tar.gz"},
	} {
		f := analyzeBinSource(&PackageContext{Name: "foo-bin", PkgbuildContent: binPkgbuild("'" + tc.src + "'"), Meta: &AurMeta{URL: tc.url}})
		if len(f) != 0 {
			t.Errorf("url=%s source %s: unexpected %v", tc.url, tc.src, ids(f))
		}
	}
}

func TestBinDomainMismatchKeepsForeignHosts(t *testing.T) {
	for _, tc := range []struct{ url, src, id string }{
		{"https://brave.com", "https://203.0.113.9/brave-browser.tar.gz", "B-BIN-DOMAIN-MISMATCH"},
		{"https://www.dropbox.com", "https://files.evil-cdn.example/dropbox.tar.gz", "B-BIN-DOMAIN-MISMATCH"},
		// a look-alike registrable domain is not the upstream's
		{"https://obsidian.md", "https://obsidian-md.download/obsidian.AppImage", "B-BIN-DOMAIN-MISMATCH"},
		// a different GitHub owner for the binary, including through raw.githubusercontent.com
		{"https://github.com/brave/brave-browser", "https://github.com/brave-release-mirror/brave/releases/download/v1/brave.zip", "B-BIN-GITHUB-ORG-MISMATCH"},
		{"https://github.com/brave/brave-browser", "https://raw.githubusercontent.com/someone/x/main/brave.AppImage", "B-BIN-GITHUB-ORG-MISMATCH"},
		// GitHub Pages of another owner
		{"https://alice.github.io/tool", "https://bob.github.io/tool/tool.tar.gz", "B-BIN-DOMAIN-MISMATCH"},
	} {
		f := analyzeBinSource(&PackageContext{Name: "foo-bin", PkgbuildContent: binPkgbuild("'" + tc.src + "'"), Meta: &AurMeta{URL: tc.url}})
		if c, ok := classOf(f, tc.id); !ok || c != ClassEvidence {
			t.Errorf("url=%s source %s: want %s evidence, got %v", tc.url, tc.src, tc.id, ids(f))
		}
	}
}

func TestNonBinaryAssetIsNarrow(t *testing.T) {
	for _, u := range []string{
		"https://x/mitmproxy-10.1.tar.gz", "https://x/apache-maven-3.9.6-bin.tar.gz",
		"https://x/license-tool-1.0.tar.gz", "https://x/bsdtar.AppImage", "https://x/app.desktop",
	} {
		if nonBinaryAsset(u) {
			t.Errorf("nonBinaryAsset(%q) = true: a binary would be skipped", u)
		}
	}
	for _, u := range []string{
		"https://x/LICENSE", "https://x/LICENSE.md", "https://x/COPYING", "https://x/gpl-3.0.txt",
		"https://x/icon.png", "https://x/logo.svg?raw=true", "https://x/SHA256SUMS", "https://x/a.tar.gz.sig",
	} {
		if !nonBinaryAsset(u) {
			t.Errorf("nonBinaryAsset(%q) = false", u)
		}
	}
}

func TestOrphanTakeoverIsContext(t *testing.T) {
	now := int64(1700000000)
	stubNowUnix(t, now)
	old := now - 3*365*86400
	ctx := &PackageContext{
		Name: "ocaml-monolith",
		Meta: &AurMeta{Submitter: "alice", Maintainer: "bob", FirstSubmitted: old},
		GitLog: []GitCommit{
			{Author: "bob", Timestamp: now},
			{Author: "alice", Timestamp: old},
		},
	}
	f := analyzeOrphanTakeover(ctx)
	if c, ok := classOf(f, "B-ORPHAN-TAKEOVER"); !ok || c != ClassContext {
		t.Fatalf("B-ORPHAN-TAKEOVER must be context; got %v", f)
	}
	if IsMalicious(Detect(ctx)) {
		t.Fatalf("an orphan adoption alone minted; findings=%v", ids(Detect(ctx)))
	}
}

func TestTyposquatSkipsYearsOldNames(t *testing.T) {
	now := int64(1700000000)
	stubNowUnix(t, now)
	// A 1-edit name registered five years ago is a real project with a similar name.
	f := analyzeName(&PackageContext{Name: "pary", Meta: &AurMeta{Name: "pary", FirstSubmitted: now - 5*365*86400}})
	if c, ok := classOf(f, "B-TYPOSQUAT"); !ok || c != ClassContext {
		t.Errorf("years-old 1-edit name: want B-TYPOSQUAT context, got %v", f)
	}
	// The live campaign's names are days old: still evidence.
	for _, name := range []string{"pary", "yat", "parru"} {
		f = analyzeName(&PackageContext{Name: name, Meta: &AurMeta{Name: name, FirstSubmitted: now - 3*86400}})
		if c, ok := classOf(f, "B-TYPOSQUAT"); !ok || c != ClassEvidence {
			t.Errorf("new 1-edit name %q: want B-TYPOSQUAT evidence, got %v", name, f)
		}
	}
	// No submission time: not established.
	f = analyzeName(&PackageContext{Name: "pary", Meta: &AurMeta{Name: "pary"}})
	if c, ok := classOf(f, "B-TYPOSQUAT"); !ok || c != ClassEvidence {
		t.Errorf("unknown age: want B-TYPOSQUAT evidence, got %v", f)
	}
}

func diffIDs(oldC, newC string) []string {
	return ids(analyzePkgbuildDiff(&PackageContext{Name: "pkg", PkgbuildContent: newC, PriorPkgbuildContent: oldC}))
}

func hasID(list []string, id string) bool {
	for _, x := range list {
		if x == id {
			return true
		}
	}
	return false
}

func TestSourceDomainChangedAllowsUpstreamMoves(t *testing.T) {
	for _, tc := range []struct{ old, new string }{
		{"https://github.com/a/b/archive/v1.tar.gz", "https://codeload.github.com/a/b/tar.gz/v2"},
		{"https://pypi.python.org/packages/source/f/foo/foo-1.tar.gz", "https://files.pythonhosted.org/packages/source/f/foo/foo-2.tar.gz"},
		{"https://pypi.io/packages/source/f/foo/foo-1.tar.gz", "https://files.pythonhosted.org/packages/source/f/foo/foo-2.tar.gz"},
		{"https://phoenixnap.dl.sourceforge.net/project/x/x-1.tar.gz", "https://downloads.sourceforge.net/project/x/x-2.tar.gz"},
		{"https://www.crosswire.org/ftpmirror/sword-1.tar.gz", "https://crosswire.org/ftpmirror/sword-2.tar.gz"},
		{"https://csc.mpi-magdeburg.mpg.de/x-1.tar.gz", "https://gitlab.mpi-magdeburg.mpg.de/x/-/archive/2/x-2.tar.gz"},
		{"https://repo.maven.apache.org/maven2/x/1/x.jar", "https://repo1.maven.org/maven2/x/2/x.jar"},
		{"https://search.cpan.org/CPAN/authors/id/A/X-1.tar.gz", "https://cpan.metacpan.org/authors/id/A/X-2.tar.gz"},
		// an org rename on the same host keeps the domain
		{"https://github.com/oldname/thinkwatt/archive/v1.tar.gz", "https://github.com/serialoverflow/thinkwatt/archive/v1.tar.gz"},
	} {
		o := "pkgname=x\nsource=(\"" + tc.old + "\")\nsha256sums=('abc')\n"
		n := "pkgname=x\nsource=(\"" + tc.new + "\")\nsha256sums=('def')\n"
		if got := diffIDs(o, n); hasID(got, "T-DIFF-SOURCE-DOMAIN-CHANGED") {
			t.Errorf("%s -> %s flagged: %v", tc.old, tc.new, got)
		}
	}
}

func TestSourceDomainChangedKeepsNewHosts(t *testing.T) {
	for _, tc := range []struct{ old, new string }{
		{"https://github.com/a/b/archive/v1.tar.gz", "https://evil.example/b-2.tar.gz"},
		{"https://downloads.sourceforge.net/project/x/x-1.tar.gz", "http://45.9.148.10/x-2.tar.gz"},
		// a gist or another user's pages site is not the same GitHub repository
		{"https://github.com/a/b/archive/v1.tar.gz", "https://gist.githubusercontent.com/z/123/raw/b.sh"},
		{"https://a.github.io/b/b-1.tar.gz", "https://z.github.io/b/b-2.tar.gz"},
	} {
		o := "pkgname=x\nsource=(\"" + tc.old + "\")\nsha256sums=('abc')\n"
		n := "pkgname=x\nsource=(\"" + tc.new + "\")\nsha256sums=('def')\n"
		if got := diffIDs(o, n); !hasID(got, "T-DIFF-SOURCE-DOMAIN-CHANGED") {
			t.Errorf("%s -> %s not flagged: %v", tc.old, tc.new, got)
		}
	}
}

func TestChecksumRemovedSkipsVCSAndDroppedPatches(t *testing.T) {
	for _, tc := range []struct{ name, old, new string }{
		{"switch to git+ (docker-gc)",
			"source=('https://raw.githubusercontent.com/spotify/docker-gc/abc/docker-gc')\nsha256sums=('0123abcd')\n",
			"source=('git+https://github.com/spotify/docker-gc.git')\nsha256sums=('SKIP')\n"},
		{"dropped local patch, git source remains",
			"source=('git+https://gitlab.com/x/y.git' 'fix-build.patch')\nsha256sums=('SKIP' '0123abcd')\n",
			"source=('git+https://gitlab.com/x/y.git')\nsha256sums=('SKIP')\n"},
		{"checksum array removed with the last patch",
			"source=(\"$pkgname::git+https://git.savannah.gnu.org/git/x.git#tag=v1\" 'a.patch')\nsha256sums=('SKIP' '0123abcd')\n",
			"source=(\"$pkgname::git+https://git.savannah.gnu.org/git/x.git#tag=v2\")\n"},
	} {
		if got := diffIDs("pkgname=x\n"+tc.old, "pkgname=x\n"+tc.new); hasID(got, "T-DIFF-CHECKSUM-REMOVED") {
			t.Errorf("%s: flagged %v", tc.name, got)
		}
	}
}

func TestChecksumRemovedKeepsTarballs(t *testing.T) {
	for _, tc := range []struct{ name, old, new string }{
		{"tarball checksum changed to SKIP",
			"source=('https://example.org/x-1.tar.gz')\nsha256sums=('0123abcd')\n",
			"source=('https://example.org/x-2.tar.gz')\nsha256sums=('SKIP')\n"},
		{"checksum array removed, tarball remains",
			"source=('https://example.org/x-1.tar.gz')\nsha256sums=('0123abcd')\n",
			"source=('https://example.org/x-2.tar.gz')\n"},
		{"unresolved variable source",
			"source=(\"${url}/archive/v1.tar.gz\")\nsha256sums=('0123abcd')\n",
			"source=(\"${url}/archive/v2.tar.gz\")\nsha256sums=('SKIP')\n"},
	} {
		if got := diffIDs("pkgname=x\n"+tc.old, "pkgname=x\n"+tc.new); !hasID(got, "T-DIFF-CHECKSUM-REMOVED") {
			t.Errorf("%s: not flagged %v", tc.name, got)
		}
	}
}

func TestHTTPSourceWithSkipChecksumIsWeakness(t *testing.T) {
	// sundtek: plain http, SKIP.
	pk := "pkgname=sundtek\npkgver=1\nsource=('http://www.sundtek.de/media/sundtek_installer_${pkgver}.sh' 'sundtek.service')\n" +
		"md5sums=('SKIP' 'd41d8cd98f00b204e9800998ecf8427e')\n"
	f := analyzeChecksum(&PackageContext{Name: "sundtek", PkgbuildContent: pk})
	if c, ok := classOf(f, "P-HTTP-SOURCE-SKIP"); !ok || c != ClassWeakness {
		t.Fatalf("want P-HTTP-SOURCE-SKIP weakness, got %v", f)
	}
	for _, f := range f {
		if f.ID == "P-HTTP-SOURCE-SKIP" && (f.CWE != "CWE-494" || f.CVSSVector == "") {
			t.Errorf("weakness must carry CWE-494 and a CVSS vector: %+v", f)
		}
	}
	for _, pk := range []string{
		// https with SKIP, http with a real checksum, a git+http VCS source
		"pkgname=a\nsource=('https://example.org/a.tar.gz')\nsha256sums=('SKIP')\n",
		"pkgname=a\nsource=('http://example.org/a.tar.gz')\nsha256sums=('0123abcd')\n",
		"pkgname=a\nsource=('git+http://example.org/a.git')\nsha256sums=('SKIP')\n",
		// per-arch arrays pair by suffix
		"pkgname=a\nsource_x86_64=('http://example.org/a.tar.gz')\nsha256sums_x86_64=('0123abcd')\n",
	} {
		if c, ok := classOf(analyzeChecksum(&PackageContext{Name: "a", PkgbuildContent: pk}), "P-HTTP-SOURCE-SKIP"); ok {
			t.Errorf("P-HTTP-SOURCE-SKIP (%s) on %q", c, pk)
		}
	}
}

func TestJuliaBuildDownloads(t *testing.T) {
	jl := func(src string) []Finding {
		f := Detect(&PackageContext{Name: "X", Ecosystem: "julia", InstallScriptContent: src})
		var out []Finding
		for _, x := range f {
			if strings.HasPrefix(x.ID, "JL-BUILD-") && x.ID != "JL-BUILD-SHELL-INTERP" {
				out = append(out, x)
			}
		}
		return out
	}
	// LKH.jl deps/build.jl: plain http, no checksum, then built and run -> CWE-494 weakness.
	lkh := "const LKH_VERSION = \"LKH-3.0.6\"\n" +
		"const LKH_SRC_URL = \"http://webhotel4.ruc.dk/~keld/research/LKH-3/$(LKH_VERSION).tgz\"\n" +
		"function download_LKH()\n    src_tarball = joinpath(@__DIR__, \"LKH.tgz\")\n    download(LKH_SRC_URL, src_tarball)\n    run(`tar xvfz $src_tarball`)\nend\n"
	if f := jl(lkh); len(f) != 1 || f[0].ID != "JL-BUILD-UNVERIFIED-DOWNLOAD" || f[0].Class != ClassWeakness || f[0].CWE != "CWE-494" {
		t.Errorf("LKH: want JL-BUILD-UNVERIFIED-DOWNLOAD weakness, got %+v", f)
	}
	// CLBlast.jl: an https GitHub tag archive is normal build logic -> context.
	clblast := "url = \"https://github.com/CNugteren/CLBlast/archive/\" * version * \".tar.gz\"\n" +
		"run(pipeline(`wget -q -O - $url`, `tar xzf -`))\n"
	if f := jl(clblast); len(f) != 1 || f[0].ID != "JL-BUILD-DOWNLOAD" || f[0].Class != ClassContext {
		t.Errorf("CLBlast: want JL-BUILD-DOWNLOAD context, got %+v", f)
	}
	// http but checksum-verified -> context.
	pinned := "download(\"http://example.org/x.tgz\", \"x.tgz\")\nbytes2hex(sha256(read(\"x.tgz\"))) == want || error(\"bad\")\n"
	if f := jl(pinned); len(f) != 1 || f[0].Class != ClassContext {
		t.Errorf("verified http download: want context, got %+v", f)
	}
	// No download at all -> nothing.
	if f := jl("run(`make -C nauty27r3`)\n"); len(f) != 0 {
		t.Errorf("no download: got %+v", f)
	}
}
