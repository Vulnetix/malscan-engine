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
	var out []Finding
	sawOrgMismatch := false

	for _, raw := range extractSourceURLs(ctx.PkgbuildContent, upstreamURL) {
		if !strings.Contains(raw, "://") {
			continue
		}
		srcDomain := extractDomain(raw)
		if srcDomain == "" {
			continue
		}
		if normalizeDomain(srcDomain) == "github.com" && normalizeDomain(upstreamDomain) == "github.com" {
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
		if normalizeDomain(srcDomain) != normalizeDomain(upstreamDomain) {
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
	if !strings.HasSuffix(normalizeDomain(seg[0]), "github.com") {
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
			out = append(out, finding("B-ORPHAN-TAKEOVER", "behavioral", 50,
				fmt.Sprintf("Adopted package with new git author (%s) — orphan takeover pattern", latest)))
		}
	}
	return out
}

func isEstablished(firstSubmitted int64) bool {
	return nowUnix()-firstSubmitted > 90*86400
}
