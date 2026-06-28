// Package ioc extracts indicators of compromise (and artifact hashes) from a
// malicious package's PKGBUILD, install scripts, and latest-commit diff. It is
// dependency-free apart from the sibling detect package (for the GitCommit type)
// so it can be reused across the VDB processors and package-firewall.
package ioc

import (
	"regexp"
	"strings"

	"github.com/vulnetix/malscan-engine/allow"
	"github.com/vulnetix/malscan-engine/detect"
)

// IOC is an indicator of compromise extracted from a malicious package. Type
// values match the production open set: domain | url | ipv4 | file-hash |
// install-command | exfil-endpoint | email | wallet | package-name.
type IOC struct {
	Type      string
	Value     string
	Ecosystem string
	Truncated bool
}

// RepoData is the subset of a cloned package repo the extractor needs.
type RepoData struct {
	PkgbuildContent string
	InstallScripts  string
	GitLog          []detect.GitCommit
}

const maxIOCs = 60

var (
	iocIPv4RE       = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`)
	iocURLRE        = regexp.MustCompile(`https?://[^\s'")\\]+`)
	iocMoneroRE     = regexp.MustCompile(`\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b`)
	iocEthRE        = regexp.MustCompile(`\b0x[a-fA-F0-9]{40}\b`)
	iocBtcRE        = regexp.MustCompile(`\b(?:bc1[a-z0-9]{25,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b`)
	iocHash64RE     = regexp.MustCompile(`\b[a-fA-F0-9]{64}\b`)
	iocInstallRE    = regexp.MustCompile(`\b(?:npm|bun|pnpm|yarn|pip|pip3)\s+(?:install|add|i)\b[^\n;&|]*`)
	emailRE         = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	checksumArrayRE = regexp.MustCompile(`(?ms)^(?:md5|sha1|sha224|sha256|sha384|sha512|b2)sums(?:_[a-zA-Z0-9_]+)?\s*=\s*\((.*?)\)`)
	hexTokenRE      = regexp.MustCompile(`[a-fA-F0-9]{32,128}`)
	hexOnlyRE       = regexp.MustCompile(`^[a-fA-F0-9]+$`)
)

// exfilHostMarkers classify a URL as an exfil/C2 endpoint rather than a source.
var exfilHostMarkers = []string{
	"discord.com/api/webhooks", "discordapp.com/api/webhooks", "api.telegram.org/bot",
	"pastebin.com", "paste.ee", "hastebin.com", "ptpb.pw", "ix.io",
	"bit.ly/", "tinyurl.com/", "t.co/", "is.gd/", "v.gd/", "short.io/",
	"duckdns.org", "no-ip.com", "ddns.net", "dynu.com", "ngrok.io", "ngrok-free.app",
	"webhook.site", "requestbin", "transfer.sh", "0x0.st", "termbin.com",
}

// ExtractIOCs pulls indicators from the PKGBUILD, install scripts, and the
// latest-commit added lines.
func ExtractIOCs(repo *RepoData) []IOC {
	if repo == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []IOC
	addedDiff := addedLines(latestDiff(repo))

	emit := func(typ, val, eco string) {
		val = strings.TrimSpace(strings.Trim(val, `"'<>`))
		if val == "" {
			return
		}
		// Drop benign indicators (reserved/placeholder IPs, registry/CDN/standards/
		// docs domains) so they never become IOCs — this is what stops legit spec
		// links and funding URLs in package source from polluting the STIX feed.
		// Wallet / file-hash / install-command types are unknown to allow.Benign and
		// are always kept.
		if allow.Benign(typ, val) {
			return
		}
		key := typ + "|" + strings.ToLower(val)
		if seen[key] || len(out) >= maxIOCs {
			return
		}
		seen[key] = true
		out = append(out, IOC{Type: typ, Value: val, Ecosystem: eco})
	}

	content := repo.PkgbuildContent + "\n" + repo.InstallScripts

	for _, u := range iocURLRE.FindAllString(content, -1) {
		if t := classifyURL(u); t != "" {
			emit(t, u, "")
		}
	}
	for _, ip := range iocIPv4RE.FindAllString(content, -1) {
		if ip == "127.0.0.1" || ip == "0.0.0.0" {
			continue
		}
		emit("ipv4", ip, "")
	}
	for _, w := range iocMoneroRE.FindAllString(content, -1) {
		emit("wallet", w, "monero")
	}
	for _, w := range iocEthRE.FindAllString(content, -1) {
		emit("wallet", w, "ethereum")
	}
	for _, w := range iocBtcRE.FindAllString(content, -1) {
		emit("wallet", w, "bitcoin")
	}
	for _, cmd := range iocInstallRE.FindAllString(content, -1) {
		emit("install-command", collapseSpace(cmd), npmEcosystem(cmd))
	}
	for _, e := range emailRE.FindAllString(content, -1) {
		emit("email", e, "")
	}

	// File hashes only from added diff lines outside checksum arrays.
	for _, line := range addedDiff {
		if strings.Contains(strings.ToLower(line), "sums") || isChecksumish(line) {
			continue
		}
		for _, h := range iocHash64RE.FindAllString(line, -1) {
			emit("file-hash", h, "sha256")
		}
	}

	return out
}

// DeclaredHashes returns the integrity checksums declared in the PKGBUILD's
// *sums=() arrays. 'SKIP' and dynamic ($-interpolated) entries are excluded.
func DeclaredHashes(repo *RepoData) []string {
	if repo == nil || repo.PkgbuildContent == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, m := range checksumArrayRE.FindAllStringSubmatch(repo.PkgbuildContent, -1) {
		for _, h := range hexTokenRE.FindAllString(m[1], -1) {
			lh := strings.ToLower(h)
			if !seen[lh] {
				seen[lh] = true
				out = append(out, h)
			}
		}
	}
	return out
}

// CandidateHashes returns every artifact hash associated with a package: the
// declared source checksums plus any 64-hex value introduced in the latest
// commit's added lines outside a checksum array.
func CandidateHashes(repo *RepoData) []string {
	if repo == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(h string) {
		lh := strings.ToLower(strings.TrimSpace(h))
		if lh == "" || seen[lh] {
			return
		}
		seen[lh] = true
		out = append(out, h)
	}
	for _, h := range DeclaredHashes(repo) {
		add(h)
	}
	for _, line := range addedLines(latestDiff(repo)) {
		if strings.Contains(strings.ToLower(line), "sums") || isChecksumish(line) {
			continue
		}
		for _, h := range iocHash64RE.FindAllString(line, -1) {
			add(h)
		}
	}
	return out
}

func latestDiff(repo *RepoData) string {
	if len(repo.GitLog) > 0 {
		return repo.GitLog[0].Diff
	}
	return ""
}

func addedLines(diff string) []string {
	if diff == "" {
		return nil
	}
	var out []string
	for l := range strings.SplitSeq(diff, "\n") {
		if strings.HasPrefix(l, "+") && !strings.HasPrefix(l, "+++") {
			out = append(out, strings.TrimPrefix(l, "+"))
		}
	}
	return out
}

func classifyURL(u string) string {
	lower := strings.ToLower(u)
	for _, m := range exfilHostMarkers {
		if strings.Contains(lower, m) {
			return "exfil-endpoint"
		}
	}
	return ""
}

func npmEcosystem(cmd string) string {
	lower := strings.ToLower(cmd)
	switch {
	case strings.HasPrefix(lower, "pip"):
		return "pypi"
	case strings.HasPrefix(lower, "npm"), strings.HasPrefix(lower, "bun"),
		strings.HasPrefix(lower, "pnpm"), strings.HasPrefix(lower, "yarn"):
		return "npm"
	}
	return ""
}

// isChecksumish reports a line that is just quoted hex tokens (a sums array body).
func isChecksumish(line string) bool {
	t := strings.TrimSpace(line)
	t = strings.Trim(t, "()")
	t = strings.ReplaceAll(t, "'", " ")
	t = strings.ReplaceAll(t, "\"", " ")
	fields := strings.Fields(t)
	if len(fields) == 0 {
		return false
	}
	for _, f := range fields {
		if f == "SKIP" {
			continue
		}
		if !iocHash64RE.MatchString(f) && len(f) < 32 {
			return false
		}
		if !hexOnlyRE.MatchString(f) && f != "SKIP" {
			return false
		}
	}
	return true
}

func collapseSpace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
