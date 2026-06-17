package detect

import "testing"

func ev() Finding      { return EvidenceFinding("B-CURL-EXEC", "behavioral", "", "download-and-execute", "") }
func entropy() Finding { return Trigger(EntropyTriggerID, "pkgbuild", "high-entropy heredoc", "") }
func trig(id string) Finding {
	return Trigger(id, "metadata", "x", "owner")
}

func TestCombinedVerdictPermutations(t *testing.T) {
	cases := []struct {
		name     string
		findings []Finding
		want     bool
		path     string
	}{
		// P0
		{"evidence alone mints", []Finding{ev()}, true, "evidence"},
		// P4
		{"known-bad owner mints", []Finding{trig(TriggerOwnerKnownBad)}, true, "owner-known-bad"},
		// P1/P2 — payload + identity
		{"entropy + ownership transfer mints", []Finding{entropy(), trig(TriggerOwnershipTransfer)}, true, "payload+identity"},
		{"entropy + orphan adoption mints", []Finding{entropy(), trig(TriggerOrphanAdoption)}, true, "payload+identity"},
		// P3 — ≥2 families WITH a change/takeover family
		{"owner-transfer + email-swap mints", []Finding{trig(TriggerOwnershipTransfer), trig(TriggerChangedEmail)}, true, "multi-identity"},
		{"takeover by fresh account (transfer + new-maintainer) mints", []Finding{trig(TriggerOwnershipTransfer), trig(TriggerNewMaintainer)}, true, "multi-identity"},
		{"orphan takeover by fresh account mints", []Finding{trig(TriggerOrphanAdoption), trig(TriggerNewMaintainer)}, true, "multi-identity"},
		// P-none — single signals, pure newness, redundant facets
		{"ownership transfer alone does NOT mint", []Finding{trig(TriggerOwnershipTransfer)}, false, ""},
		{"orphan adoption alone does NOT mint", []Finding{trig(TriggerOrphanAdoption)}, false, ""},
		{"new maintainer alone does NOT mint", []Finding{trig(TriggerNewMaintainer)}, false, ""},
		{"entropy alone does NOT mint", []Finding{entropy()}, false, ""},
		{"changed email alone does NOT mint", []Finding{trig(TriggerChangedEmail)}, false, ""},
		// PURE NEWNESS = brand-new legit package signature → never mints
		{"new-maintainer + new-reporter (new package) does NOT mint", []Finding{trig(TriggerNewMaintainer), trig(TriggerNewReporter)}, false, ""},
		{"new-maintainer + new-contributor does NOT mint", []Finding{trig(TriggerNewMaintainer), trig(TriggerNewContributor)}, false, ""},
		// redundant facets of ONE owner event (both owner-change family) → counts once → no mint
		{"transfer + orphan (one owner-change family) does NOT mint", []Finding{
			trig(TriggerOwnershipTransfer), trig(TriggerOrphanAdoption),
		}, false, ""},
	}
	for _, c := range cases {
		v := CombinedVerdict(c.findings)
		if v.Malicious != c.want {
			t.Errorf("%s: Malicious=%v want %v (path=%q reasons=%v)", c.name, v.Malicious, c.want, v.Path, v.Reasons)
		}
		if c.want && v.Path != c.path {
			t.Errorf("%s: path=%q want %q", c.name, v.Path, c.path)
		}
		if c.want && len(v.Reasons) == 0 {
			t.Errorf("%s: minted with no reasons (IOC detail would be empty)", c.name)
		}
	}
}

func TestOwnershipTriggersDescribeCompounding(t *testing.T) {
	prior := &PackageMeta{Maintainer: "alice"}
	meta := &PackageMeta{Maintainer: "bob", Submitter: "alice"}
	fs := OwnershipTriggers(meta, prior, nil)
	if len(fs) == 0 {
		t.Fatal("expected ownership triggers")
	}
	for _, f := range fs {
		if f.Class != ClassTrigger {
			t.Errorf("%s should be ClassTrigger (never standalone evidence)", f.ID)
		}
	}
	// transfer alone (no lookup, submitter==prior maintainer) must not mint
	if CombinedVerdict(fs).Malicious {
		// alice->bob transfer + alice!=bob orphan-adoption are BOTH "owner" family → no P3
		t.Errorf("lone ownership change (one family) must not mint; got %+v", CombinedVerdict(fs))
	}
}
