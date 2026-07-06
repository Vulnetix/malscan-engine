// Package detect (malscan-engine) is a Go port of the malicious-PKGBUILD detection engine
// from Sohimaster/traur (https://github.com/Sohimaster/traur, MIT licensed).
//
// Unlike traur, this port does NOT compute a weighted trust score or tier.
// Per Vulnetix policy, the engine only adopts traur's *factual* evaluations:
// every detector emits Findings, and any single Finding whose Class is
// ClassEvidence is sufficient to mark a package malicious. Reputation-only
// signals (votes, popularity, stars, missing license, package age) are emitted
// as ClassContext and recorded as package metadata — they never, on their own,
// mint a malware advisory. Human review can overturn a malicious verdict
// downstream.
//
// Attribution: the pattern database (data/patterns.toml) and the detection
// heuristics are derived from traur, Copyright (c) 2026 Sohimaster, MIT License.
package detect

// Class marks whether a Finding is factual malicious evidence (mints a CVE) or
// reputational context (recorded as metadata only).
type Class string

const (
	// ClassEvidence is a factual malicious-code/behaviour detection. Any one
	// evidence Finding marks the package malicious.
	ClassEvidence Class = "evidence"
	// ClassContext is a reputation/risk signal. Recorded as metadata; never
	// mints a CVE on its own.
	ClassContext Class = "context"
	// ClassTrigger is a weak corroborating signal that NEVER mints on its own,
	// but combines with a high-entropy payload to mint (see IsMaliciousCombined).
	// The high-entropy heredoc and the supply-chain metadata signals
	// (new reporter / maintainer / contributor, changed maintainer/contributor
	// email) are all triggers.
	ClassTrigger Class = "trigger"
)

// Combination-gate signal ids. These are referenced by both the engine and the
// processor (which builds the DB/git-derived metadata triggers).
const (
	// EntropyTriggerID is the high-entropy heredoc detection. It is the required
	// anchor of the combination path — a high-entropy payload alone is not proof
	// of malice (legitimate packages embed base64 icons, certs, fonts), but a
	// high-entropy payload introduced alongside a supply-chain trigger is.
	EntropyTriggerID = "SA-HIGH-ENTROPY-HEREDOC"

	// Metadata triggers — built by the processor from ThreatActor (DB) state and
	// the package git history. Each is a ClassTrigger.
	TriggerNewReporter    = "MT-NEW-REPORTER"    // AUR submitter never seen before
	TriggerNewMaintainer  = "MT-NEW-MAINTAINER"  // AUR maintainer never seen before
	TriggerNewContributor = "MT-NEW-CONTRIBUTOR" // latest-commit author never seen before
	TriggerChangedEmail   = "MT-CHANGED-EMAIL"   // maintainer/contributor email changed (name irrelevant)

	// KnownBadHashID marks a declared/source/diff hash that matches a known-bad
	// hash (embedded list or MalwareIoc). It is ClassEvidence — mints on its own.
	KnownBadHashID = "B-KNOWN-BAD-HASH"

	// ── Ownership / hijack triggers (cross-registry) ────────────────────────────
	// A package/repo hijack is frequently JUST a change in ownership. By itself
	// that is NOT proof — legitimate maintainer hand-offs and orphan adoptions
	// happen constantly — so every ownership signal is a ClassTrigger the engine
	// CORRELATES with other indicators (see CombinedVerdict). The findings/IOCs
	// these produce state explicitly that the signal is a compounding
	// ownership-change indicator, not standalone evidence.

	// TriggerOwnershipTransfer — the established prior owner/maintainer was
	// replaced by a DIFFERENT current owner (the package changed hands). Generic
	// across registries (npm _npmUser, PyPI/RubyGems maintainer, AUR Maintainer…).
	TriggerOwnershipTransfer = "MT-OWNERSHIP-TRANSFER"
	// TriggerOrphanAdoption — the original Submitter no longer maintains the
	// package and a different account now does (orphan/abandonment takeover).
	TriggerOrphanAdoption = "MT-ORPHAN-ADOPTION"
	// TriggerOwnerKnownBad — the current owner matches a known-bad ThreatActor in
	// our DB (the processor supplies this fact). Strongest ownership signal (P4).
	TriggerOwnerKnownBad = "MT-OWNER-KNOWN-BAD"
)

// identityFamily groups ownership/identity triggers into INDEPENDENT families so
// the combination gate counts distinct *kinds* of signal, not redundant facets
// of one event (ownership-transfer + orphan-adoption are both "owner-change" →
// count once). Returns "" for non-identity triggers. These families corroborate
// a payload in the P1/P2 path only — no combination of them mints without a
// payload (see CombinedVerdict).
func identityFamily(id string) string {
	switch id {
	case TriggerOwnershipTransfer, TriggerOrphanAdoption:
		return "owner-change"
	case TriggerChangedEmail:
		return "email"
	case TriggerNewMaintainer:
		return "new-maintainer"
	case TriggerNewContributor:
		return "new-contributor"
	case TriggerNewReporter:
		return "new-reporter"
	}
	return ""
}

// isPayloadTrigger reports whether a trigger is a payload/behaviour signal (the
// high-entropy heredoc today) vs. an ownership/identity signal. A payload trigger
// correlated with any identity trigger is the P1/P2 mint path.
func isPayloadTrigger(id string) bool { return id == EntropyTriggerID }

// Trigger builds a ClassTrigger Finding. Used by the processor to inject the
// DB/git-derived supply-chain metadata triggers into the finding set before the
// combination gate runs.
func Trigger(id, category, desc, matchedLine string) Finding {
	return Finding{
		ID: id, Category: category, Class: ClassTrigger,
		CWE: DefaultMalwareCWE, Description: desc, MatchedLine: matchedLine,
	}
}

// EvidenceFinding builds a ClassEvidence Finding (mints on its own). Used by the
// processor for the known-bad-hash detection.
func EvidenceFinding(id, category, cwe, desc, matchedLine string) Finding {
	if cwe == "" {
		cwe = DefaultMalwareCWE
	}
	return Finding{
		ID: id, Category: category, Class: ClassEvidence,
		CWE: cwe, Description: desc, MatchedLine: matchedLine,
	}
}

// Finding is a single detection emitted by a feature.
type Finding struct {
	ID          string // signal id, e.g. "P-CURL-PIPE", "SA-VAR-CONCAT-EXEC"
	Category    string // "pkgbuild" | "install" | "source-url" | "gtfobins" | "shell" | "name" | "behavioral" | "temporal" | "metadata"
	Class       Class  // ClassEvidence | ClassContext
	CWE         string // mapped CWE id (best-effort), e.g. "CWE-506"
	Points      int    // traur's original weight, retained for reference/sorting only
	Description string // human-readable explanation
	MatchedLine string // the triggering line (trimmed), when pattern-based
}

// PackageContext carries all data a detector needs. Originally modelled on
// traur's PackageContext (src/shared/models.go), it is now ecosystem-agnostic:
// every processor (AUR, Homebrew, npm, PyPI, RubyGems, …) maps its package's
// primary build/manifest script into PkgbuildContent and its install hooks into
// InstallScriptContent, and the content-based detectors run uniformly. The
// reputation metadata (PackageMeta) and git history are optional.
type PackageContext struct {
	Name string // package name

	// Ecosystem is the registry slug ("aur", "homebrew", "npm", "pypi",
	// "rubygems", "go", "cargo", "nuget", …). Optional; lets detectors and
	// downstream consumers branch on ecosystem and label findings.
	Ecosystem string

	// Capabilities gates which detectors Detect runs, keyed by the shared
	// capability keys (the Cap* constants; see the config package). nil — the
	// default — enables every detector; a key set false short-circuits that
	// detector. Populate it from the per-ecosystem config a human authored in
	// the frontend (config.EcosystemConfig.Capabilities).
	Capabilities map[string]bool

	// Reputation/identity metadata (nil if unavailable). Originally the AUR RPC
	// v5 `info` subset; reused across ecosystems via the generic field set.
	Meta *PackageMeta

	PkgbuildContent      string // primary build/manifest script text (PKGBUILD, Ruby formula, package.json scripts, setup.py, build.rs, …); "" if unavailable
	InstallScriptContent string // concatenated install hooks (*.install, npm pre/post-install, init.ps1, build.jl, …)
	PriorPkgbuildContent string // build script from the previous revision (for diff)

	// PkgbuildExecutes declares whether PkgbuildContent is an auto-execution
	// recipe whose commands run at build/install time (AUR PKGBUILD
	// build()/package(), Alpine APKBUILD, a Homebrew formula install/post_install)
	// rather than runtime source or a manually-run manifest (npm package.json
	// scripts, a package's shipped sources). False — the zero value, so existing
	// callers are unaffected — makes dual-use gtfobins commands (hook_only
	// patterns; e.g. bare aria2c/docker/npx-remote) found in PkgbuildContent
	// ClassContext instead of evidence. InstallScriptContent is always treated as
	// a hook surface. override_gate patterns (reverse/bind shells, curl|sh) are
	// unaffected and mint on every surface.
	PkgbuildExecutes bool

	GitLog []GitCommit // newest-first commit list from the package's source repo

	// MaintainerPackages: other packages owned by the same maintainer (for
	// batch-upload detection). Optional.
	MaintainerPackages []PackageMeta

	GithubStars    *int // upstream GitHub stargazers (nil if unknown / not GitHub)
	GithubNotFound bool // upstream URL is a GitHub repo that returned 404

	AurComments []string // recent registry comment bodies (optional)
}

// PackageMeta is the generic reputation/identity subset detectors use. Field
// names retain their AUR origin but apply across ecosystems (e.g. NumVotes /
// Popularity map to downloads/stars, Submitter to the original publisher).
type PackageMeta struct {
	Name           string
	PackageBase    string
	URL            string // upstream project URL
	NumVotes       int
	Popularity     float64
	OutOfDate      int64 // unix seconds; 0 = not flagged
	Maintainer     string
	Submitter      string
	FirstSubmitted int64 // unix seconds
	LastModified   int64 // unix seconds
	License        []string
	Depends        []string
	MakeDepends    []string
	Source         []string // source=() / download URLs declared by the manifest
}

// AurMeta is the original name of PackageMeta, retained as a type alias so the
// AUR and Homebrew processors (and any external callers) keep compiling.
type AurMeta = PackageMeta

// GitCommit is one commit from the AUR package git repo.
type GitCommit struct {
	Author    string
	Email     string // commit author email (for actor linkage; detectors ignore it)
	Timestamp int64  // unix seconds
	Diff      string // unified diff for this commit ("" if not collected)
}
