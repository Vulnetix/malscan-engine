package allow

import "testing"

func TestInstallerHost(t *testing.T) {
	yes := []string{
		"astral.sh", "docs.astral.sh", "sh.rustup.rs", "ollama.com", "bun.sh", "get.docker.com",
		"deno.land", "pixi.sh",
		"ASTRAL.SH", " astral.sh ",
	}
	for _, h := range yes {
		if !InstallerHost(h) {
			t.Errorf("InstallerHost(%q)=false, want true", h)
		}
	}
	// Hosts where a payload is routinely staged, or that merely host user content, must
	// never be here: raw.githubusercontent.com carried 98 OpenSSF-confirmed packages.
	no := []string{
		"raw.githubusercontent.com", "github.com", "gist.githubusercontent.com", "webhook.site",
		"pastebin.com", "bit.ly", "evil.com", "evil.sh", "astral.sh.evil.com", "notastral.sh",
		"s3.amazonaws.com", "ngrok.io", "", "203.0.113.9", "example.com", "x.example", "localhost",
	}
	for _, h := range no {
		if InstallerHost(h) {
			t.Errorf("InstallerHost(%q)=true, want false", h)
		}
	}
}

func TestSourceFileNamesAreNotDomains(t *testing.T) {
	for _, h := range []string{"build.rs", "setup.py", "main.py", "lib.rs", "conftest.py", "install.sh", "__init__.py", "README.md", "Build.RS"} {
		if !CodeTokenDomain(h) {
			t.Errorf("%q should read as a file name, not a domain", h)
		}
	}
	// Real registrable domains on the same TLDs have a brand label, not a file stem.
	for _, h := range []string{"ntfy.sh", "bun.sh", "pixi.sh", "crates.rs", "lumis.sh", "evilc2.sh", "payload.cc", "sub.build.rs", "build.rs.evil.com"} {
		if SourceFileName(h) {
			t.Errorf("%q is a real-looking host and must not be treated as a file name", h)
		}
	}
}
