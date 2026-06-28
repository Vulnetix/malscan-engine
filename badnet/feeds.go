package badnet

import (
	"encoding/json"
	"fmt"
	"os"
)

// feed is one upstream threat-intel source.
type feed struct {
	name   string
	url    string
	format format
}

type feedConfigFile struct {
	SchemaVersion string             `json:"schema_version"`
	Feeds         []feedConfigSource `json:"feeds"`
}

type feedConfigSource struct {
	Key     string `json:"key"`
	URL     string `json:"url"`
	Parser  string `json:"parser"`
	Enabled *bool  `json:"enabled"`
}

var fallbackFeeds = []feed{
	{"dshield-block", "https://www.dshield.org/block.txt", fmtIPList},
	{"dshield-ipsascii", "https://www.dshield.org/ipsascii.html", fmtIPList},
	{"crowdsec-intelligence", "https://feeds.crowdsec.net/free/2be9a716-39b8-5c18-bc9e-4ba7aefd8831.json", fmtMISP},
	{"dandelionsprout-antimalware", "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt", fmtHosts},
	{"feodotracker-recommended", "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt", fmtIPList},
	{"urlhaus-hosts", "https://urlhaus.abuse.ch/downloads/hostfile/", fmtHosts},
	{"isc-intelfeed", "https://isc.sans.edu/api/intelfeed", fmtMixed},
	{"isc-cloudips", "https://isc.sans.edu/api/cloudips", fmtIPList},
	{"firehol-level3", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset", fmtNetset},
	{"binarydefense-banlist", "https://binarydefense.com/banlist.txt", fmtIPList},
	{"aper-phishing-reply", "https://svn.code.sf.net/p/aper/code/phishing_reply_addresses", fmtEmails},
	{"projecthoneypot-p-rss", "https://www.projecthoneypot.org/list_of_ips.php?t=p&rss=1", fmtRSS},
	{"projecthoneypot-rss", "https://www.projecthoneypot.org/list_of_ips.php?rss=1", fmtRSS},
	{"cinsscore-badguys", "http://cinsscore.com/list/ci-badguys.txt", fmtIPList},
	{"alienvault-generic", "https://reputation.alienvault.com/reputation.generic", fmtIPList},
	{"alienvault-data", "https://reputation.alienvault.com/reputation.data", fmtIPList},
	{"bruteforceblocker", "https://danger.rulez.sk/projects/bruteforceblocker/blist.php", fmtIPList},
}

// Feeds is the curated set of public blocklists aggregated into the badnet
// definitions. Each entry's format selects the parser; the classifier then keeps
// only individual (non-CIDR) IPs, valid domains, and emails, minus allow-listed
// values. It is the single source of truth shared by the embedded-data generator
// (cmd/genblocklist, the pre-commit/release path) and the runtime Fetch used by
// the CLI's `malscan --fetch-definitions`.
var feeds = loadConfiguredFeeds()

func loadConfiguredFeeds() []feed {
	b, err := dataFS.ReadFile("data/feeds.json")
	if err != nil {
		return fallbackFeeds
	}
	out, err := parseFeedConfig(b)
	if err != nil {
		return fallbackFeeds
	}
	return out
}

func parseFeedConfig(b []byte) ([]feed, error) {
	var cfg feedConfigFile
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	out := make([]feed, 0, len(cfg.Feeds))
	for _, src := range cfg.Feeds {
		if src.Enabled != nil && !*src.Enabled {
			continue
		}
		if src.Key == "" || src.URL == "" {
			continue
		}
		parser, ok := parseFormat(src.Parser)
		if !ok {
			return nil, fmt.Errorf("feed %q uses unknown parser %q", src.Key, src.Parser)
		}
		out = append(out, feed{name: src.Key, url: src.URL, format: parser})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no enabled feeds")
	}
	return out, nil
}

func loadFeedsFile(path string) ([]feed, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseFeedConfig(b)
}

func parseFormat(v string) (format, bool) {
	switch format(v) {
	case fmtIPList:
		return fmtIPList, true
	case fmtNetset:
		return fmtNetset, true
	case fmtHosts:
		return fmtHosts, true
	case fmtRSS:
		return fmtRSS, true
	case fmtEmails:
		return fmtEmails, true
	case fmtMixed:
		return fmtMixed, true
	case fmtMISP:
		return fmtMISP, true
	default:
		return "", false
	}
}

// FeedURLs returns the source feed URLs (for diagnostics / docs).
func FeedURLs() []string {
	out := make([]string, len(feeds))
	for i, f := range feeds {
		out[i] = f.url
	}
	return out
}
