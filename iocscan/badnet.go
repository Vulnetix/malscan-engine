package iocscan

import (
	"net"

	"github.com/vulnetix/malscan-engine/badnet"
)

// badnetIndicatorName / Description label the synthesised indicators so evidence
// is attributable to the aggregated public threat-intel blocklists.
const (
	badnetIndicatorName = "known-bad host (threat-intel blocklist)"
	badnetDescription   = "matched an aggregated public threat-intel blocklist (badnet)"
)

// addEmbeddedBadnet merges the engine's embedded badnet blocklists into the set.
func (s *IndicatorSet) addEmbeddedBadnet() { s.AddBadnetSet(badnet.New()) }

// AddBadnetSet merges a badnet blocklist (individual IPs + domains) into the
// indicator set. Entries are routed through Add, so the same allow / code-token /
// version-IP guards that protect the STIX path apply here too. Emails are not
// merged — the matcher has no email channel (use badnet.Set.HasEmail directly).
func (s *IndicatorSet) AddBadnetSet(bn *badnet.Set) {
	if bn == nil {
		return
	}
	for _, ip := range bn.IPs() {
		t := TypeIPv4
		if p := net.ParseIP(ip); p != nil && p.To4() == nil {
			t = TypeIPv6
		}
		s.Add(&Indicator{
			Type:        t,
			Value:       ip,
			Name:        badnetIndicatorName,
			Description: badnetDescription,
			Labels:      []string{"malicious-activity", "source:threat-intel-blocklist"},
		})
	}
	for _, d := range bn.Domains() {
		s.Add(&Indicator{
			Type:        TypeDomain,
			Value:       d,
			Name:        badnetIndicatorName,
			Description: badnetDescription,
			Labels:      []string{"malicious-activity", "source:threat-intel-blocklist"},
		})
	}
}
