package allow

import "strings"

// installerHosts are hosts whose `curl … | sh` is the vendor's own DOCUMENTED install
// method. A package that mentions one of these lines is telling the user how to install
// someone else's tool, which is not evidence about the package.
//
// This list is separate from Domain on purpose. Domain answers "is this host an
// indicator of compromise?" and so includes github.com and raw.githubusercontent.com,
// which are not IOCs. For a pipe-to-shell those two hosts are exactly where attackers
// stage payloads: measured 2026-10-17 over every P-CURL-PIPE mint in production,
// raw.githubusercontent.com carried 530 mints, 98 of them in packages OpenSSF independently
// confirmed as malware. They must stay evidence, so they are not here.
//
// Every entry below carried mints in production and appeared in no OpenSSF-confirmed
// package (astral.sh 522 mints/0 confirmed, sh.rustup.rs 101/0, ollama.com 56/0, bun.sh
// 41/0, ...). Entries are exact registrable hosts; subdomains match (docs.astral.sh).
// Keep it to a vendor's own install endpoint: a host that merely hosts user content
// (a gist, a paste, a bucket, a tunnel) never belongs here.
var installerHosts = map[string]bool{
	"astral.sh": true, "rustup.rs": true, "ollama.com": true, "ollama.ai": true,
	"bun.sh": true, "bun.com": true, "deno.land": true, "pixi.sh": true,
	"get.docker.com": true, "fly.io": true, "tailscale.com": true,
	"deb.nodesource.com": true, "rpm.nodesource.com": true, "get.pnpm.io": true,
	"get.k3s.io": true, "pyenv.run": true, "mise.run": true, "elan.lean-lang.org": true,
	"get.nextflow.io": true, "install.python-poetry.org": true, "claude.ai": true,
	"cursor.com": true, "opencode.ai": true, "codecov.io": true, "get.maestro.mobile.dev": true,
}

// InstallerHost reports whether host is a vendor's canonical install endpoint. Subdomains of
// a listed host match. Reserved example hosts (example.com, *.example) are deliberately NOT
// here: the engine's own fixtures use them as stand-ins for a hostile URL.
func InstallerHost(host string) bool {
	h := normHost(host)
	if h == "" {
		return false
	}
	for d := range installerHosts {
		if h == d || strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	return false
}
