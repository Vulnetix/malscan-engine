package detect

import "regexp"

// Tor hidden-service (.onion) detection. A package that fetches sources from or
// beacons to a .onion address is almost never legitimate: Tor hidden services
// are a common command-and-control (C2) / exfiltration channel because they
// hide the operator's infrastructure. This is factual malicious evidence (mints
// on its own).
//
// Scans the PKGBUILD/formula, install scripts, and the latest-commit diff so a
// .onion address introduced in any of them is caught (the source_url pattern
// section only ever saw the PKGBUILD).
var onionRE = regexp.MustCompile(`(?i)\b[a-z2-7]{16,56}\.onion\b|\.onion[/:]`)

func analyzeOnion(ctx *PackageContext) []Finding {
	for _, content := range []string{ctx.PkgbuildContent, ctx.InstallScriptContent, latestCommitDiff(ctx)} {
		if content == "" {
			continue
		}
		if loc := onionRE.FindString(content); loc != "" {
			return []Finding{{
				ID:          "P-ONION-C2",
				Category:    "source-url",
				Class:       ClassEvidence,
				CWE:         "CWE-94", // C2 channel — improper control of code/command
				Points:      65,
				Description: "Tor .onion hidden-service address (possible C2 / exfiltration endpoint)",
				MatchedLine: firstMatchingLine(content, onionRE),
			}}
		}
	}
	return nil
}

// latestCommitDiff returns the unified diff of the newest commit, if collected.
func latestCommitDiff(ctx *PackageContext) string {
	if len(ctx.GitLog) > 0 {
		return ctx.GitLog[0].Diff
	}
	return ""
}
