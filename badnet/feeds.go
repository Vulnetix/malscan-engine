package badnet

// feed is one upstream threat-intel source.
type feed struct {
	name   string
	url    string
	format format
}

// Feeds is the curated set of public blocklists aggregated into the badnet
// definitions. Each entry's format selects the parser; the classifier then keeps
// only individual (non-CIDR) IPs, valid domains, and emails, minus allow-listed
// values. It is the single source of truth shared by the embedded-data generator
// (cmd/genblocklist, the pre-commit/release path) and the runtime Fetch used by
// the CLI's `malscan --fetch-definitions`.
var feeds = []feed{
	{"dshield-block", "https://www.dshield.org/block.txt", fmtIPList},
	{"dshield-ipsascii", "https://www.dshield.org/ipsascii.html", fmtIPList},
	{"dandelionsprout-antimalware", "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt", fmtHosts},
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

// FeedURLs returns the source feed URLs (for diagnostics / docs).
func FeedURLs() []string {
	out := make([]string, len(feeds))
	for i, f := range feeds {
		out[i] = f.url
	}
	return out
}
