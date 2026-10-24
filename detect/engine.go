package detect

import (
	"strings"
	"time"
)

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

	// A pypi package's runtime source is read without its docstrings and comments, and data
	// literals (deny-lists, keyword lists, test vectors) are context, not evidence. See
	// pythonLibraryViews. The install surface (setup.py) is never rewritten.
	pkgView := ctx.PkgbuildContent
	if isPythonLibrary(ctx) {
		docView, execView := pythonLibraryViews(ctx.PkgbuildContent)
		lib := *ctx
		lib.PkgbuildContent = docView
		ctx = &lib
		pkgView = execView
	}

	pkgSurface := SurfaceLibrary
	if ctx.PkgbuildExecutes {
		pkgSurface = SurfaceBuild
	}
	if ctx.PkgbuildContent != "" {
		n := len(f)
		if ctx.capEnabled(CapManifestPatterns) {
			f = matchSectionView(ctx.PkgbuildContent, pkgView, "pkgbuild_analysis", "pkgbuild", "", ctx.PkgbuildExecutes, ctx.Ecosystem, f)
		}
		if ctx.capEnabled(CapSourceURLPatterns) {
			f = matchSectionView(ctx.PkgbuildContent, pkgView, "source_url_analysis", "source-url", "", ctx.PkgbuildExecutes, ctx.Ecosystem, f)
		}
		if ctx.capEnabled(CapGTFObins) {
			f = matchSectionView(ctx.PkgbuildContent, pkgView, "gtfobins_analysis", "gtfobins", "", ctx.PkgbuildExecutes, ctx.Ecosystem, f)
		}
		if ctx.capEnabled(CapShellObfuscation) {
			f = append(f, analyzeShell(ctx.PkgbuildContent, "", "")...)
		}
		setSurface(f[n:], pkgSurface)
	}
	if ctx.InstallScriptContent != "" && ctx.capEnabled(CapInstallScript) {
		n := len(f)
		f = matchSection(ctx.InstallScriptContent, "install_script_analysis", "install", "", true, ctx.Ecosystem, f)
		if ctx.capEnabled(CapGTFObins) {
			f = matchSection(ctx.InstallScriptContent, "gtfobins_analysis", "gtfobins", "IS-", true, ctx.Ecosystem, f)
		}
		if ctx.capEnabled(CapShellObfuscation) {
			f = append(f, analyzeShell(ctx.InstallScriptContent, "IS-", "(in install script)")...)
		}
		setSurface(f[n:], SurfaceInstall)
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

// isPythonLibrary reports whether PkgbuildContent is a pypi package's runtime source (not an
// executing recipe), the content pythonLibraryViews may rewrite.
func isPythonLibrary(ctx *PackageContext) bool {
	return !ctx.PkgbuildExecutes && ctx.PkgbuildContent != "" &&
		strings.EqualFold(strings.TrimSpace(ctx.Ecosystem), "pypi")
}

// setSurface stamps a surface on findings a detector did not stamp itself.
func setSurface(fs []Finding, surface string) {
	for i := range fs {
		if fs[i].Surface == "" {
			fs[i].Surface = surface
		}
	}
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

// Weaknesses returns only the ClassWeakness findings from a Detect result:
// dual-use code-execution capabilities that are reported as vulnerability
// candidates and are never, on their own, a reason to call a package malicious.
func Weaknesses(findings []Finding) []Finding {
	var out []Finding
	for _, f := range findings {
		if f.Class == ClassWeakness {
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

	// HighFidelity qualifies a malicious verdict; it never changes it. It is false when the
	// whole basis is a single evidence finding in non-executing library content
	// (Surface == SurfaceLibrary) with no install-script hit of any non-context class: one
	// string in a package's runtime source, which is where the audited false positives sit.
	// Downstream it gates automatic approval (vdb-manager requireHighFidelity); a
	// low-fidelity mint still mints and goes to human review. Always false when not malicious.
	HighFidelity bool
}

// highFidelity applies the Verdict.HighFidelity rule to an evidence verdict's findings.
// Indicators are counted by id: one rule declared in two sections (P-DISCORD-WEBHOOK is both a
// manifest and a source-url rule) is still one indicator.
func highFidelity(findings []Finding) bool {
	ids := map[string]bool{}
	allLibrary := true
	for _, f := range findings {
		if f.Surface == SurfaceInstall && f.Class != ClassContext {
			return true // the install surface corroborates
		}
		if f.Class == ClassEvidence {
			ids[f.ID] = true
			allLibrary = allLibrary && f.Surface == SurfaceLibrary
		}
	}
	return !(len(ids) == 1 && allLibrary)
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
			return Verdict{Malicious: true, Path: "evidence", Reasons: []string{describe(f)}, HighFidelity: highFidelity(findings)}
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
		return Verdict{Malicious: true, Path: "payload+identity", Reasons: reasons, HighFidelity: true}
	}
	// P-none — evidence-free: a payload alone (legit embedded blob), or any
	// ownership/identity/reputation signal(s) with no payload. Correlation only.
	return Verdict{Malicious: false}
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
