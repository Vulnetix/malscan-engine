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
	f = append(f, analyzeHomograph(ctx)...)
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

// Verdict is the combination-gate result. Path/Reasons let the processor record
// WHY a record was minted — so an ownership-change IOC's detail can state which
// compounding path corroborated it (it is correlation, never standalone proof).
type Verdict struct {
	Malicious bool
	Path      string   // "" | "evidence" | "owner-known-bad" | "payload+identity" | "multi-identity"
	Reasons   []string // human-readable compounding indicators (trigger ids/descriptions)
}

// CombinedVerdict applies the combination gate and explains the result. The
// permutations are deliberately distinct — a package/repo hijack is often JUST a
// change in ownership, which is ONE correlatable indicator, not proof:
//
//	P0  any single ClassEvidence finding (download-and-execute, reverse shell,
//	    exfil, .onion C2, known-bad hash).                         → malicious
//	P4  the current owner matches a known-bad ThreatActor          → malicious
//	    (TriggerOwnerKnownBad; the owner is a cataloged attacker).
//	P1/P2  a payload/behaviour trigger (high-entropy heredoc) AND ≥1 ownership/
//	    identity trigger — the takeover revision that also injects code.→ malicious
//	P3  ≥2 INDEPENDENT identity families AND ≥1 is a CHANGE/takeover family
//	    (owner-change or email-swap) — e.g. owner-transfer + email-swap, or an
//	    orphan takeover by a new account — metadata correlation, no payload.
//	                                                               → malicious
//
// NOT malicious (recorded as correlation context for human/downstream review):
//   - a SINGLE ownership/identity signal alone (an orphan adoption, a lone owner
//     change, a lone email change). Legitimate hand-offs do this.
//   - PURE-NEWNESS combinations: new-maintainer + new-reporter (+ new-contributor)
//     are the signature of a brand-new LEGITIMATE package (its submitter and
//     maintainer are both first-seen). No change family → never mints.
//   - entropy alone (legit embedded base64/cert/font blobs).
//   - redundant facets of ONE event: ownership-transfer + orphan-adoption are both
//     the "owner-change" family → counts once.
func CombinedVerdict(findings []Finding) Verdict {
	// P0 — any factual evidence.
	for _, f := range findings {
		if f.Class == ClassEvidence {
			return Verdict{true, "evidence", []string{describe(f)}}
		}
	}

	hasPayload := false
	var payloadReason string
	families := map[string]string{} // family -> a representative reason
	ownerKnownBad := ""
	for _, f := range findings {
		if f.Class != ClassTrigger {
			continue
		}
		if f.ID == TriggerOwnerKnownBad {
			ownerKnownBad = describe(f)
			continue
		}
		if isPayloadTrigger(f.ID) {
			hasPayload = true
			payloadReason = describe(f)
			continue
		}
		if fam := identityFamily(f.ID); fam != "" {
			families[fam] = describe(f)
		}
	}

	// P4 — owner is a known-bad actor.
	if ownerKnownBad != "" {
		return Verdict{true, "owner-known-bad", []string{ownerKnownBad}}
	}
	// P1/P2 — payload/behaviour correlated with any ownership/identity change.
	if hasPayload && len(families) >= 1 {
		reasons := []string{payloadReason}
		for _, r := range families {
			reasons = append(reasons, r)
		}
		return Verdict{true, "payload+identity", reasons}
	}
	// P3 — ≥2 INDEPENDENT identity families AND at least one is a CHANGE/takeover
	// family (so a brand-new package's new-maintainer+new-reporter never mints).
	hasChange := false
	for fam := range families {
		if isChangeFamily(fam) {
			hasChange = true
			break
		}
	}
	if len(families) >= 2 && hasChange {
		reasons := make([]string, 0, len(families))
		for _, r := range families {
			reasons = append(reasons, r)
		}
		return Verdict{true, "multi-identity", reasons}
	}
	// P-none — a single ownership signal / entropy alone: correlation only.
	return Verdict{false, "", nil}
}

// describe yields a short reason string for a finding (id + description).
func describe(f Finding) string {
	if f.Description != "" {
		return f.ID + ": " + f.Description
	}
	return f.ID
}

// IsMaliciousCombined is the boolean form of CombinedVerdict (back-compat).
func IsMaliciousCombined(findings []Finding) bool {
	return CombinedVerdict(findings).Malicious
}
