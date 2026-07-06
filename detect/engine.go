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
// Each detector is gated by its capability key (ctx.capEnabled): a config that
// disabled it for this ecosystem short-circuits it here, so the engine runs only
// what a human left enabled in the frontend. A nil ctx.Capabilities (the
// default) runs everything, so existing callers are unaffected.
func Detect(ctx *PackageContext) []Finding {
	loadPatterns()
	var f []Finding

	if ctx.PkgbuildContent != "" {
		if ctx.capEnabled(CapManifestPatterns) {
			f = matchSection(ctx.PkgbuildContent, "pkgbuild_analysis", "pkgbuild", "", ctx.PkgbuildExecutes, f)
		}
		if ctx.capEnabled(CapSourceURLPatterns) {
			f = matchSection(ctx.PkgbuildContent, "source_url_analysis", "source-url", "", ctx.PkgbuildExecutes, f)
		}
		if ctx.capEnabled(CapGTFObins) {
			f = matchSection(ctx.PkgbuildContent, "gtfobins_analysis", "gtfobins", "", ctx.PkgbuildExecutes, f)
		}
		if ctx.capEnabled(CapShellObfuscation) {
			f = append(f, analyzeShell(ctx.PkgbuildContent, "", "")...)
		}
	}
	if ctx.InstallScriptContent != "" && ctx.capEnabled(CapInstallScript) {
		f = matchSection(ctx.InstallScriptContent, "install_script_analysis", "install", "", true, f)
		if ctx.capEnabled(CapGTFObins) {
			f = matchSection(ctx.InstallScriptContent, "gtfobins_analysis", "gtfobins", "IS-", true, f)
		}
		if ctx.capEnabled(CapShellObfuscation) {
			f = append(f, analyzeShell(ctx.InstallScriptContent, "IS-", "(in install script)")...)
		}
	}

	if ctx.capEnabled(CapOnionC2) {
		f = append(f, analyzeOnion(ctx)...)
	}
	if ctx.capEnabled(CapHomograph) {
		f = append(f, analyzeHomograph(ctx)...)
	}
	if ctx.capEnabled(CapChecksum) {
		f = append(f, analyzeChecksum(ctx)...)
	}
	if ctx.capEnabled(CapNameTyposquat) {
		f = append(f, analyzeName(ctx)...)
	}
	if ctx.capEnabled(CapBinSource) {
		f = append(f, analyzeBinSource(ctx)...)
	}
	if ctx.capEnabled(CapOrphanTakeover) {
		f = append(f, analyzeOrphanTakeover(ctx)...)
	}
	if ctx.capEnabled(CapGitHistory) {
		f = append(f, analyzeGitHistory(ctx)...)
	}
	if ctx.capEnabled(CapManifestDiff) {
		f = append(f, analyzePkgbuildDiff(ctx)...)
	}
	if ctx.capEnabled(CapMetadataReputation) {
		f = append(f, analyzeMetadata(ctx)...)
	}
	if ctx.capEnabled(CapMaintainerBatch) {
		f = append(f, analyzeMaintainer(ctx)...)
	}
	if ctx.capEnabled(CapGithubStars) {
		f = append(f, analyzeGithubStars(ctx)...)
	}
	if ctx.capEnabled(CapRegistryComments) {
		f = append(f, analyzeAurComments(ctx)...)
	}
	if ctx.capEnabled(CapBadActorBehaviors) {
		f = append(f, analyzeBadActorBehaviors(ctx)...)
	}

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
	Path      string   // "" | "evidence" | "payload+identity"
	Reasons   []string // human-readable compounding indicators (trigger ids/descriptions)
}

// CombinedVerdict applies the combination gate and explains the result.
//
// CORE RULE: a malicious verdict REQUIRES content — a ClassEvidence finding or a
// payload/behaviour trigger. Ownership / identity / reputation signals (a change
// of owner, an email swap, an orphan/new maintainer, or even an owner that
// matches a known-bad actor) are NEVER a standalone or metadata-only reason to
// mint. They are reputation correlation that only strengthens a content finding.
// This is deliberate: metadata-only verdicts are the dominant source of
// whole-package false positives — one legitimate (often famous) maintainer gets
// wrongly catalogued as bad and every package they publish is then tarred.
//
//	P0  any single ClassEvidence finding (download-and-execute, reverse shell,
//	    exfil, .onion C2, known-bad hash).                            → malicious
//	P1/P2  a payload/behaviour trigger (high-entropy heredoc) AND ≥1 ownership/
//	    identity signal — a change of owner/email, an orphan/new maintainer, or an
//	    owner matching a known-bad actor: the takeover revision that ALSO injects
//	    or obfuscates code.                                           → malicious
//
// NOT malicious (recorded as correlation context for human/downstream review):
//   - ANY ownership/identity/reputation signal, or any COMBINATION of them, with
//     no corroborating payload/evidence — including an owner that matches a
//     known-bad actor (MT-OWNER-KNOWN-BAD). On their own these are frequently
//     legitimate hand-offs; they mint ONLY alongside a payload.
//   - entropy alone (legit embedded base64/cert/font blobs).
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

	// P1/P2 — a payload/behaviour trigger corroborated by ANY ownership/identity
	// signal (a change family, a newness family, or a known-bad owner). Without a
	// payload, no combination of metadata signals mints: ownership/identity is
	// correlation, never standalone proof. A known-bad owner is the strongest such
	// corroborator but is itself only reputation, so it too requires the payload.
	if hasPayload && (len(families) >= 1 || ownerKnownBad != "") {
		reasons := []string{payloadReason}
		if ownerKnownBad != "" {
			reasons = append(reasons, ownerKnownBad)
		}
		for _, r := range families {
			reasons = append(reasons, r)
		}
		return Verdict{true, "payload+identity", reasons}
	}
	// P-none — evidence-free: a payload alone (legit embedded blob), or any
	// ownership/identity/reputation signal(s) with no payload. Correlation only.
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
