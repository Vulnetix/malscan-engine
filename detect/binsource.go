package detect

import (
	"fmt"
	"regexp"
	"strings"
)

// bin-source verification + orphan-takeover — ports of traur
// bin_source_verification + orphan_takeover_analysis. A -bin package whose
// download host differs from the declared upstream, and a takeover of an
// adopted package by a new git author, are factual evidence. A bare
// submitter≠maintainer difference is context.

var (
	binSourceArraysRE = regexp.MustCompile(`(?ms)^source(?:_[a-zA-Z0-9_]+)?\s*=\s*\((.*?)\)`)
	binURLTokenRE     = regexp.MustCompile(`['"]([^'"]+)['"]|(\S+)`)
	binURLVarRE       = regexp.MustCompile(`\$\{url\}|\$url`)
	binUnresolvedVar  = regexp.MustCompile(`\$\{?\w+\}?`)
)

func analyzeBinSource(ctx *PackageContext) []Finding {
	if !strings.HasSuffix(ctx.Name, "-bin") || ctx.PkgbuildContent == "" || ctx.Meta == nil || ctx.Meta.URL == "" {
		return nil
	}
	upstreamURL := ctx.Meta.URL
	upstreamDomain := extractDomain(upstreamURL)
	if upstreamDomain == "" {
		return nil
	}
	upstreamOrg := extractGithubOrg(upstreamURL)
	upstreamOnGithub := githubHost(upstreamDomain)
	if org, ok := githubPagesOrg(upstreamDomain); ok {
		// url=https://org.github.io/project is the org's own GitHub presence.
		upstreamOrg, upstreamOnGithub = org, true
	}
	var out []Finding
	sawOrgMismatch := false

	for _, raw := range extractSourceURLs(ctx.PkgbuildContent, upstreamURL) {
		if !remoteDownloadURL(raw) {
			// file://, a bare local name: nothing is downloaded.
			continue
		}
		srcDomain := extractDomain(raw)
		if srcDomain == "" {
			continue
		}
		if binSourceRegistryHost(srcDomain) || nonBinaryAsset(raw) {
			// A licence text, an icon, a checksum list or a package fetched from the npm or
			// PyPI registry is not the -bin package's binary.
			continue
		}
		if githubHost(srcDomain) && upstreamOnGithub {
			// github.com, codeload.github.com and raw/objects.githubusercontent.com are one
			// host for this question: what matters is whose repository it is.
			srcOrg := extractGithubOrg(raw)
			if upstreamOrg != "" && srcOrg != "" && !strings.EqualFold(upstreamOrg, srcOrg) && !sawOrgMismatch {
				sawOrgMismatch = true
				f := finding("B-BIN-GITHUB-ORG-MISMATCH", "behavioral", 50,
					fmt.Sprintf("-bin package upstream is github.com/%s but source downloads from github.com/%s", upstreamOrg, srcOrg))
				f.MatchedLine = raw
				out = append(out, f)
			}
			continue
		}
		if githubHost(srcDomain) && githubOrgNamesDomain(extractGithubOrg(raw), upstreamDomain) {
			// url=https://app.lizardbyte.dev, source github.com/LizardByte/...: the project's own org.
			continue
		}
		if registrableDomain(srcDomain) != registrableDomain(upstreamDomain) {
			f := finding("B-BIN-DOMAIN-MISMATCH", "behavioral", 30,
				fmt.Sprintf("-bin package upstream is %s but source downloads from %s", upstreamDomain, srcDomain))
			f.MatchedLine = raw
			out = append(out, f)
		}
	}
	return out
}

func extractSourceURLs(content, upstreamURL string) []string {
	var urls []string
	for _, caps := range binSourceArraysRE.FindAllStringSubmatch(content, -1) {
		body := caps[1]
		for _, tc := range binURLTokenRE.FindAllStringSubmatch(body, -1) {
			raw := tc[1]
			if raw == "" {
				raw = tc[2]
			}
			if i := strings.Index(raw, "+http"); i >= 0 {
				raw = "http" + raw[i+5:]
			}
			resolved := binURLVarRE.ReplaceAllString(raw, upstreamURL)
			if binUnresolvedVar.MatchString(resolved) {
				continue
			}
			if i := strings.Index(resolved, "::"); i >= 0 {
				resolved = resolved[i+2:]
			}
			urls = append(urls, resolved)
		}
	}
	return urls
}

func extractDomain(url string) string {
	parts := strings.SplitN(url, "://", 2)
	if len(parts) < 2 {
		return ""
	}
	host := parts[1]
	if i := strings.Index(host, "/"); i >= 0 {
		host = host[:i]
	}
	if i := strings.Index(host, ":"); i >= 0 {
		host = host[:i]
	}
	return strings.ToLower(host)
}

func extractGithubOrg(url string) string {
	parts := strings.SplitN(url, "://", 2)
	if len(parts) < 2 {
		return ""
	}
	seg := strings.Split(parts[1], "/")
	if len(seg) < 2 {
		return ""
	}
	if !githubHost(extractDomain(url)) {
		return ""
	}
	if seg[1] == "" {
		return ""
	}
	return strings.ToLower(seg[1])
}

func normalizeDomain(domain string) string {
	d := strings.ToLower(domain)
	for _, prefix := range []string{"www.", "dl.", "download."} {
		if rest, ok := strings.CutPrefix(d, prefix); ok {
			return rest
		}
	}
	return d
}

// multiLabelSuffixes are public suffixes of two or more labels: a registrable domain is one label
// more than the longest of these that a host ends with, and otherwise the last two labels.
//
// The list is a small, conservative stand-in for the Public Suffix List (no new dependency). It
// holds the country second levels that package sources actually use, and the shared hosting
// suffixes where every subdomain belongs to a different owner (alice.github.io and
// bob.github.io are not one site). A suffix missing from the list makes two hosts compare
// EQUAL only when they share their last two labels, so an omission can hide a mismatch only
// under a multi-label ccTLD that is not listed here.
var multiLabelSuffixes = map[string]bool{
	// country second levels
	"co.uk": true, "org.uk": true, "ac.uk": true, "gov.uk": true, "me.uk": true, "net.uk": true, "ltd.uk": true, "plc.uk": true,
	"com.au": true, "net.au": true, "org.au": true, "edu.au": true, "gov.au": true, "id.au": true, "asn.au": true,
	"co.nz": true, "net.nz": true, "org.nz": true, "ac.nz": true, "govt.nz": true,
	"co.jp": true, "ne.jp": true, "or.jp": true, "ac.jp": true, "go.jp": true, "gr.jp": true,
	"com.cn": true, "net.cn": true, "org.cn": true, "edu.cn": true, "gov.cn": true, "ac.cn": true,
	"com.br": true, "net.br": true, "org.br": true, "gov.br": true,
	"com.tw": true, "net.tw": true, "org.tw": true, "edu.tw": true, "idv.tw": true,
	"co.kr": true, "or.kr": true, "ne.kr": true, "ac.kr": true, "re.kr": true,
	"co.in": true, "net.in": true, "org.in": true, "ac.in": true, "gov.in": true,
	"com.hk": true, "org.hk": true, "com.sg": true, "edu.sg": true, "com.my": true,
	"co.id": true, "or.id": true, "ac.id": true, "co.il": true, "org.il": true, "ac.il": true,
	"co.za": true, "org.za": true, "ac.za": true, "com.mx": true, "com.ar": true, "com.tr": true,
	"com.ua": true, "org.ua": true, "com.pl": true, "net.pl": true, "org.pl": true, "edu.pl": true,
	"com.vn": true, "co.th": true, "ac.th": true, "in.th": true, "com.ru": true, "org.ru": true,
	// shared hosting: each subdomain is its own owner
	"github.io": true, "gitlab.io": true, "codeberg.page": true, "sourceforge.io": true,
	"githubusercontent.com": true, "googleusercontent.com": true, "dropboxusercontent.com": true,
	"pages.dev": true, "workers.dev": true, "netlify.app": true, "vercel.app": true, "web.app": true,
	"firebaseapp.com": true, "appspot.com": true, "herokuapp.com": true, "blogspot.com": true,
	"readthedocs.io": true, "s3.amazonaws.com": true, "amazonaws.com": true, "cloudfront.net": true,
	"azurewebsites.net": true, "azureedge.net": true, "blob.core.windows.net": true,
	"onrender.com": true, "fly.dev": true, "surge.sh": true, "gitee.io": true, "pythonanywhere.com": true,
	"ngrok.io": true, "ngrok-free.app": true, "duckdns.org": true, "ddns.net": true, "no-ip.org": true,
}

// registrableDomain returns host's registrable domain (eTLD+1): download.beeper.com and
// beeper-desktop.download.beeper.com are both beeper.com. An IP literal is returned as is.
func registrableDomain(host string) string {
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if h == "" || strings.Trim(h, "0123456789.") == "" || strings.Contains(h, ":") {
		return h
	}
	labels := strings.Split(h, ".")
	if len(labels) <= 2 {
		return h
	}
	// The longest listed suffix wins: s3.amazonaws.com before amazonaws.com.
	for i := 1; i < len(labels)-1; i++ {
		if multiLabelSuffixes[strings.Join(labels[i:], ".")] {
			return strings.Join(labels[i-1:], ".")
		}
	}
	return strings.Join(labels[len(labels)-2:], ".")
}

// githubHost reports whether host serves GitHub repository content addressed by /<org>/<repo>.
func githubHost(host string) bool {
	switch normalizeDomain(host) {
	case "github.com", "codeload.github.com", "raw.githubusercontent.com", "objects.githubusercontent.com":
		return true
	}
	return false
}

// githubPagesOrg returns the org of an <org>.github.io host.
func githubPagesOrg(host string) (string, bool) {
	org, ok := strings.CutSuffix(strings.ToLower(host), ".github.io")
	if !ok || org == "" || strings.Contains(org, ".") {
		return "", false
	}
	return org, true
}

// githubOrgNamesDomain reports whether a GitHub org is the project the upstream domain names:
// org LizardByte for app.lizardbyte.dev. The org must equal one whole label of the host, so a
// short org cannot match by accident inside a longer name.
func githubOrgNamesDomain(org, upstreamDomain string) bool {
	if len(org) < 3 {
		return false
	}
	for _, l := range strings.Split(strings.ToLower(upstreamDomain), ".") {
		if l == strings.ToLower(org) {
			return true
		}
	}
	return false
}

// remoteDownloadURL reports whether a source entry is fetched over the network.
func remoteDownloadURL(raw string) bool {
	s := strings.ToLower(raw)
	for _, scheme := range []string{"http://", "https://", "ftp://", "ftps://"} {
		if strings.HasPrefix(s, scheme) {
			return true
		}
	}
	return false
}

// binSourceRegistryHost is a package registry a -bin package may take a prebuilt package from:
// the npm registry tarball or the PyPI wheel IS the upstream's own release.
func binSourceRegistryHost(host string) bool {
	switch normalizeDomain(host) {
	case "registry.npmjs.org", "registry.yarnpkg.com", "files.pythonhosted.org", "pypi.org", "pypi.io", "pypi.python.org":
		return true
	}
	return false
}

// nonBinaryAssetRE matches the last path segment of a source that cannot be the package's
// binary: a licence or EULA text, an icon, a checksum list or a signature.
var nonBinaryAssetRE = regexp.MustCompile(`(?i)` +
	`^(?:(?:un)?licen[cs]e|copying|notice|eula|terms(?:[-_]of[-_](?:use|service))?)(?:[-_.][\w+-]*)?(?:\.(?:txt|md|html?|rtf|pdf))?$` +
	`|^(?:a|l)?gpl(?:-?v?[\d.]+)?(?:\.(?:txt|md|html?))?$` +
	`|\.(?:png|svg|svgz|ico|icns|xpm|jpe?g|gif|webp|bmp)$` +
	`|^(?:sha(?:1|256|512)sums?|md5sums?|checksums?)(?:\.txt)?$` +
	`|\.(?:sha(?:1|256|512)|md5|sig|asc|minisig|sign)$`)

// nonBinaryAsset reports whether a source URL names a licence, icon, checksum or signature file.
func nonBinaryAsset(raw string) bool {
	u := raw
	if i := strings.IndexAny(u, "?#"); i >= 0 {
		u = u[:i]
	}
	u = strings.TrimRight(u, "/")
	seg := u[strings.LastIndex(u, "/")+1:]
	if seg == "" {
		return false
	}
	return nonBinaryAssetRE.MatchString(seg)
}

func analyzeOrphanTakeover(ctx *PackageContext) []Finding {
	if ctx.Meta == nil || ctx.Meta.Submitter == "" || ctx.Meta.Maintainer == "" {
		return nil
	}
	if ctx.Meta.Submitter == ctx.Meta.Maintainer {
		return nil
	}
	var out []Finding
	out = append(out, ctxFinding("B-SUBMITTER-CHANGED", "behavioral", 15,
		fmt.Sprintf("Package maintainer (%s) differs from original submitter (%s)", ctx.Meta.Maintainer, ctx.Meta.Submitter)))

	if len(ctx.GitLog) >= 2 && isEstablished(ctx.Meta.FirstSubmitted) {
		latest := ctx.GitLog[0].Author
		priorHas := false
		for _, c := range ctx.GitLog[1:] {
			if c.Author == latest {
				priorHas = true
				break
			}
		}
		if !priorHas {
			// Context, never evidence. An adopter's first commit is how every orphaned AUR package
			// gets a new maintainer: 237 of the 814 audited set-A AUR mints rested on this alone and
			// were routine adoptions (version bumps, nvchecker files, maintainer lines). A takeover
			// that injects code is caught by what the code does.
			out = append(out, contextFinding("B-ORPHAN-TAKEOVER", "behavioral", 50,
				fmt.Sprintf("Adopted package with new git author (%s) — orphan takeover pattern", latest)))
		}
	}
	return out
}

func isEstablished(firstSubmitted int64) bool {
	return nowUnix()-firstSubmitted > 90*86400
}
