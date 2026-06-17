package detect

import (
	"fmt"
	"strings"
)

// OwnerLookup supplies the DB-derived facts the dependency-free engine cannot
// compute itself. Each registry processor implements it over the shared malware
// DB (ThreatActor table + per-source maintainer history).
type OwnerLookup interface {
	// SeenOwner reports whether this owner/maintainer identifier has been
	// observed before (an established account) vs. brand-new.
	SeenOwner(identifier string) bool
	// KnownBadActor reports whether this identifier matches a known-bad
	// ThreatActor already cataloged in the malware DB.
	KnownBadActor(identifier string) bool
}

// OwnershipTriggers builds the cross-registry ownership/hijack triggers from a
// package's current and prior identity metadata. EVERY finding it returns is a
// ClassTrigger — a change of ownership is one correlatable indicator, NEVER proof
// on its own (legitimate hand-offs and orphan adoptions happen constantly). The
// engine decides whether they compound into a detection in CombinedVerdict
// (P1–P4); a lone ownership signal is recorded as correlation context only.
//
// Each description states the compounding nature explicitly, so any IOC/detection
// record a processor derives from these triggers carries that fact in its detail.
// Works for any registry: map the registry's "who controls this package now"
// to PackageMeta.Maintainer and the original publisher to PackageMeta.Submitter
// (npm _npmUser, PyPI/RubyGems/NuGet maintainer, AUR Maintainer, Go module owner…).
//
// `prior` is the same package's previous-revision metadata (nil if unavailable);
// `lookup` is nil-safe (the "never-seen" and "known-bad" triggers are skipped).
func OwnershipTriggers(meta, prior *PackageMeta, lookup OwnerLookup) []Finding {
	var out []Finding
	if meta == nil {
		return out
	}
	cur := strings.TrimSpace(meta.Maintainer)

	// MT-OWNERSHIP-TRANSFER — the package changed hands (prior owner → different
	// current owner).
	if prior != nil {
		prev := strings.TrimSpace(prior.Maintainer)
		if prev != "" && cur != "" && !strings.EqualFold(prev, cur) {
			out = append(out, Trigger(TriggerOwnershipTransfer, "metadata",
				fmt.Sprintf("ownership transferred: maintainer changed %q → %q. Compounding hijack indicator "+
					"— NOT proof alone; the engine correlates it with payload/email/contributor changes "+
					"(legitimate hand-offs also transfer ownership).", prev, cur),
				cur))
		}
	}

	// MT-ORPHAN-ADOPTION — the original submitter no longer maintains it.
	if sub := strings.TrimSpace(meta.Submitter); sub != "" && cur != "" && !strings.EqualFold(sub, cur) {
		out = append(out, Trigger(TriggerOrphanAdoption, "metadata",
			fmt.Sprintf("orphan/abandonment takeover: current maintainer %q differs from original submitter %q "+
				"(the submitter is the likely VICTIM, not the actor). Compounding indicator — correlate with "+
				"other signals; not proof alone.", cur, sub),
			cur))
	}

	if lookup != nil && cur != "" {
		// MT-NEW-MAINTAINER — current owner is a never-before-seen account.
		if !lookup.SeenOwner(cur) {
			out = append(out, Trigger(TriggerNewMaintainer, "metadata",
				fmt.Sprintf("current maintainer %q has not been seen before on any package. Compounding "+
					"indicator — correlate; a fresh account is not proof alone.", cur),
				cur))
		}
		// MT-OWNER-KNOWN-BAD — current owner is a cataloged attacker (P4).
		if lookup.KnownBadActor(cur) {
			out = append(out, Trigger(TriggerOwnerKnownBad, "metadata",
				fmt.Sprintf("current owner %q matches a known-bad threat actor already cataloged in the malware DB "+
					"— strong ownership signal.", cur),
				cur))
		}
	}

	return out
}
