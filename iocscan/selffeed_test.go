package iocscan

import (
	"testing"

	"github.com/vulnetix/malscan-engine/badnet"
)

// badnetNew is a thin alias so the test reads the same way a consumer would.
func badnetNew() *badnet.Set { return badnet.New() }

// vdb-manager generates https://vulnetix.com/malscan-stix/ from its own
// MalwareHost/MalwareIoc rows. If its processors then read that same index back
// through this loader, an indicator it published becomes "third-party known-bad"
// evidence for its own next scan and a single false positive is self-confirming.
// DisableVulnetixIndex must skip the index WITHOUT failing the load, so a caller
// that opts out still gets a usable set from the remaining sources rather than an
// error that turns ioc-scan off entirely.
//
// Note what Load does and does not include: the embedded badnet is merged by
// Scan (via Options.NoBadnet), NOT by Load. A caller that uses Load + NewMatcher
// directly therefore has only the remote feeds, and once this flag is set it must
// add badnet.New() itself to keep any third-party indicators at all.
func TestDisableVulnetixIndexDoesNotFailTheLoad(t *testing.T) {
	l := &FeedLoader{
		DisableVulnetixIndex: true,
		DisableTweetFeed:     true, // no network at all in this test
		CacheDir:             t.TempDir(),
	}
	set, _, err := l.Load("npm")
	if err != nil {
		t.Fatalf("Load returned %v — disabling our own index must not fail the load", err)
	}
	if set == nil {
		t.Fatal("Load returned a nil set")
	}
	// Empty is expected here: no index, no TweetFeed, and Load never merges the
	// embedded badnet. The point is that it is a clean empty rather than an error.
	t.Logf("indicators from Load alone with everything disabled: %d", set.Len())

	// With badnet added the way a Load+NewMatcher caller must, the set is usable.
	set.AddBadnetSet(badnetNew())
	if set.Empty() {
		t.Error("set still empty after AddBadnetSet — third-party indicators are missing")
	}
	t.Logf("indicators after adding the embedded badnet: %d", set.Len())
}

// The index remains the default for every other consumer, for whom it genuinely
// is third-party.
func TestVulnetixIndexIsStillTheDefault(t *testing.T) {
	l := &FeedLoader{}
	if got := l.indexURL(); got != DefaultIndexURL {
		t.Errorf("indexURL() = %q, want %q", got, DefaultIndexURL)
	}
	if l.DisableVulnetixIndex {
		t.Error("DisableVulnetixIndex must default to false — opt-out, not opt-in")
	}
}
