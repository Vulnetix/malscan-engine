package detect

import "time"

// nowUnix returns the current unix time in seconds. It is a package var so
// tests can pin "now" for age-based detectors.
var nowUnix = func() int64 { return time.Now().Unix() }

// Detect runs every detector over ctx and returns all findings.
//
// Pattern targeting mirrors traur:
//   - PKGBUILD: pkgbuild_analysis, source_url_analysis, gtfobins_analysis
//   - install scripts: install_script_analysis, gtfobins_analysis (IS- prefix)
//   - shell analysis runs over both (IS- prefix for install)
//
// Findings carry a Class: ClassEvidence detections are factual malicious
// indicators (any one marks the package malicious); ClassContext detections are
// reputation/risk signals recorded as metadata only.
func Detect(ctx *PackageContext) []Finding {
	loadPatterns()
	var f []Finding

	if ctx.PkgbuildContent != "" {
		f = matchSection(ctx.PkgbuildContent, "pkgbuild_analysis", "pkgbuild", "", f)
		f = matchSection(ctx.PkgbuildContent, "source_url_analysis", "source-url", "", f)
		f = matchSection(ctx.PkgbuildContent, "gtfobins_analysis", "gtfobins", "", f)
		f = append(f, analyzeShell(ctx.PkgbuildContent, "", "")...)
	}
	if ctx.InstallScriptContent != "" {
		f = matchSection(ctx.InstallScriptContent, "install_script_analysis", "install", "", f)
		f = matchSection(ctx.InstallScriptContent, "gtfobins_analysis", "gtfobins", "IS-", f)
		f = append(f, analyzeShell(ctx.InstallScriptContent, "IS-", "(in install script)")...)
	}

	f = append(f, analyzeOnion(ctx)...)
	f = append(f, analyzeChecksum(ctx)...)
	f = append(f, analyzeName(ctx)...)
	f = append(f, analyzeBinSource(ctx)...)
	f = append(f, analyzeOrphanTakeover(ctx)...)
	f = append(f, analyzeGitHistory(ctx)...)
	f = append(f, analyzePkgbuildDiff(ctx)...)
	f = append(f, analyzeMetadata(ctx)...)
	f = append(f, analyzeMaintainer(ctx)...)
	f = append(f, analyzeGithubStars(ctx)...)
	f = append(f, analyzeAurComments(ctx)...)

	return f
}

// Evidence returns only the ClassEvidence findings from a Detect result.
func Evidence(findings []Finding) []Finding {
	var out []Finding
	for _, f := range findings {
		if f.Class == ClassEvidence {
			out = append(out, f)
		}
	}
	return out
}

// Context returns only the ClassContext findings.
func Context(findings []Finding) []Finding {
	var out []Finding
	for _, f := range findings {
		if f.Class == ClassContext {
			out = append(out, f)
		}
	}
	return out
}

// Triggers returns only the ClassTrigger findings (entropy + metadata signals).
func Triggers(findings []Finding) []Finding {
	var out []Finding
	for _, f := range findings {
		if f.Class == ClassTrigger {
			out = append(out, f)
		}
	}
	return out
}

// IsMalicious reports whether any evidence finding fired.
func IsMalicious(findings []Finding) bool {
	for _, f := range findings {
		if f.Class == ClassEvidence {
			return true
		}
	}
	return false
}

// IsMaliciousCombined applies the combination gate over the full finding set
// (engine findings plus the processor's DB/git-derived metadata triggers):
//
//   - any single ClassEvidence finding marks the package malicious (the strong
//     download-and-execute / reverse-shell / exfil / known-bad-hash rules); OR
//   - the combination path: a high-entropy payload (EntropyTriggerID) AND at
//     least one OTHER distinct trigger (new reporter/maintainer/contributor or
//     changed maintainer/contributor email).
//
// Entropy alone never mints (it fires on legitimate embedded base64/cert/font
// blobs). Metadata triggers alone never mint, and metadata-only combinations do
// NOT mint either — every brand-new legitimate AUR package necessarily has a
// previously-unseen submitter and maintainer. Entropy is the required anchor.
func IsMaliciousCombined(findings []Finding) bool {
	if IsMalicious(findings) {
		return true
	}
	hasEntropy := false
	otherTriggers := map[string]bool{}
	for _, f := range findings {
		if f.Class != ClassTrigger {
			continue
		}
		if f.ID == EntropyTriggerID {
			hasEntropy = true
			continue
		}
		otherTriggers[f.ID] = true
	}
	return hasEntropy && len(otherTriggers) >= 1
}
