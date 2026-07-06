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
		// P1/P2 — payload + identity (the ONLY mint path for ownership signals)
		{"entropy + ownership transfer mints", []Finding{entropy(), trig(TriggerOwnershipTransfer)}, true, "payload+identity"},
		{"entropy + orphan adoption mints", []Finding{entropy(), trig(TriggerOrphanAdoption)}, true, "payload+identity"},
		// owner-known-bad is corroboration, not proof: mints ONLY with a payload.
		{"known-bad owner + payload mints", []Finding{entropy(), trig(TriggerOwnerKnownBad)}, true, "payload+identity"},
		// P-none — ownership/identity/reputation signals never mint without a payload
		{"known-bad owner ALONE does NOT mint", []Finding{trig(TriggerOwnerKnownBad)}, false, ""},
		{"known-bad owner + email-swap (no payload) does NOT mint", []Finding{trig(TriggerOwnerKnownBad), trig(TriggerChangedEmail)}, false, ""},
		{"owner-transfer + email-swap (metadata only) does NOT mint", []Finding{trig(TriggerOwnershipTransfer), trig(TriggerChangedEmail)}, false, ""},
		{"transfer + new-maintainer (metadata only) does NOT mint", []Finding{trig(TriggerOwnershipTransfer), trig(TriggerNewMaintainer)}, false, ""},
		{"orphan + new-maintainer (metadata only) does NOT mint", []Finding{trig(TriggerOrphanAdoption), trig(TriggerNewMaintainer)}, false, ""},
		// single signals / pure newness / entropy alone
		{"ownership transfer alone does NOT mint", []Finding{trig(TriggerOwnershipTransfer)}, false, ""},
		{"orphan adoption alone does NOT mint", []Finding{trig(TriggerOrphanAdoption)}, false, ""},
		{"new maintainer alone does NOT mint", []Finding{trig(TriggerNewMaintainer)}, false, ""},
		{"entropy alone does NOT mint", []Finding{entropy()}, false, ""},
		{"changed email alone does NOT mint", []Finding{trig(TriggerChangedEmail)}, false, ""},
		{"new-maintainer + new-reporter (new package) does NOT mint", []Finding{trig(TriggerNewMaintainer), trig(TriggerNewReporter)}, false, ""},
		{"new-maintainer + new-contributor does NOT mint", []Finding{trig(TriggerNewMaintainer), trig(TriggerNewContributor)}, false, ""},
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
