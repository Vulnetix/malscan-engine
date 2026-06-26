package detect

// Capability keys gate which detectors run for a package. They are the contract
// shared with the Rust frontend (frontend/src/model.rs `CAPABILITIES`) and the
// persisted per-ecosystem config (the sibling `config` package). A package's
// enabled set is carried on PackageContext.Capabilities and consulted by Detect;
// the four trailing keys name detectors invoked OUTSIDE Detect (by the
// processor), which should gate them via config.EcosystemConfig.Enabled.
const (
	CapManifestPatterns   = "manifest-patterns"
	CapSourceURLPatterns  = "source-url-patterns"
	CapGTFObins           = "gtfobins"
	CapShellObfuscation   = "shell-obfuscation"
	CapInstallScript      = "install-script"
	CapOnionC2            = "onion-c2"
	CapHomograph          = "homograph"
	CapChecksum           = "checksum"
	CapNameTyposquat      = "name-typosquat"
	CapBinSource          = "bin-source"
	CapManifestDiff       = "manifest-diff"
	CapOrphanTakeover     = "orphan-takeover"
	CapGitHistory         = "git-history"
	CapMetadataReputation = "metadata-reputation"
	CapMaintainerBatch    = "maintainer-batch"
	CapGithubStars        = "github-stars"
	CapRegistryComments   = "registry-comments"

	// Invoked outside Detect (gate via config.EcosystemConfig.Enabled):
	CapOwnershipHijack = "ownership-hijack"
	CapBadHash         = "badhash"
	CapIOCExtract      = "ioc-extract"
	CapGoodKeys        = "goodkeys"

	// CapIOCScan gates the iocscan package — a network-and-filesystem capability
	// that pulls domain/IP/URL indicators from the public STIX feeds and scans a
	// working directory (and, optionally, ELF binaries) for files referencing
	// them. Like the other keys above it is invoked OUTSIDE Detect (it performs
	// I/O); gate it via config.EcosystemConfig.Enabled.
	CapIOCScan = "ioc-scan"
)

// capEnabled reports whether a capability is active for this context. A nil
// Capabilities map (the default) enables everything; a key absent from a
// non-nil map is also enabled, so a config need only record disabled
// capabilities and a newly added detector still runs against an older config.
func (ctx *PackageContext) capEnabled(key string) bool {
	if ctx.Capabilities == nil {
		return true
	}
	if v, ok := ctx.Capabilities[key]; ok {
		return v
	}
	return true
}
