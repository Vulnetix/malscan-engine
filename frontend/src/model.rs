//! The engine model, mirrored for the UI.
//!
//! Two static catalogs describe what the `malscan-engine` can do:
//!
//!   * [`ECOSYSTEMS`] — the registry slugs the engine recognises
//!     (`detect/model.go`, `PackageContext.Ecosystem`), with a sensible default
//!     registry endpoint for each.
//!   * [`CAPABILITIES`] — every detector / supporting module the engine runs,
//!     with the set of ecosystems for which it is meaningful.
//!
//! The `engine_ref` field on each capability names the Go symbol / signal-id
//! family it maps to, so this table can be checked against the engine source.
//!
//! Support matrix rationale (grounded in the Go source):
//!   * Content detectors that run over `PkgbuildContent` / `InstallScriptContent`
//!     (`detect/engine.go::Detect`) apply to every ecosystem — every processor
//!     maps its primary build/manifest script into `PkgbuildContent`.
//!   * `install-script` is restricted to registries with lifecycle/install hooks
//!     (AUR `.install`, Homebrew `post_install`, npm pre/post-install, PyPI
//!     `setup.py`, RubyGems `extconf.rb`, NuGet `init.ps1`); Go and Cargo have no
//!     equivalent install hook (Cargo's `build.rs` is a *build* script and maps
//!     to `PkgbuildContent`).
//!   * `checksum` parses PKGBUILD-style inline `sha256sums=()` arrays
//!     (`detect/checksum.go`) — AUR and Homebrew only.
//!   * `bin-source` keys off the AUR `-bin` suffix convention
//!     (`detect/binsource.go`).
//!   * `orphan-takeover` / `git-history` need a maintainer identity plus package
//!     git history — the git-backed registries (AUR, Homebrew).
//!   * `registry-comments` scans registry comment bodies, which only AUR has.

use eframe::egui::Color32;

/// A registry the engine can label findings for.
pub struct Ecosystem {
    /// Registry slug used by `PackageContext.Ecosystem` (e.g. `"npm"`).
    pub slug: &'static str,
    /// Human-friendly name shown in the switcher.
    pub name: &'static str,
    /// Default registry API endpoint (editable in the UI, saved via the stub API).
    pub default_endpoint: &'static str,
}

/// The registry slugs from `detect/model.go` (`PackageContext.Ecosystem`).
pub const ECOSYSTEMS: &[Ecosystem] = &[
    Ecosystem {
        slug: "aur",
        name: "Arch User Repository",
        default_endpoint: "https://aur.archlinux.org/rpc/v5",
    },
    Ecosystem {
        slug: "homebrew",
        name: "Homebrew",
        default_endpoint: "https://formulae.brew.sh/api",
    },
    Ecosystem {
        slug: "npm",
        name: "npm",
        default_endpoint: "https://registry.npmjs.org",
    },
    Ecosystem {
        slug: "pypi",
        name: "PyPI",
        default_endpoint: "https://pypi.org/pypi",
    },
    Ecosystem {
        slug: "rubygems",
        name: "RubyGems",
        default_endpoint: "https://rubygems.org/api/v1",
    },
    Ecosystem {
        slug: "go",
        name: "Go modules",
        default_endpoint: "https://proxy.golang.org",
    },
    Ecosystem {
        slug: "cargo",
        name: "crates.io",
        default_endpoint: "https://crates.io/api/v1",
    },
    Ecosystem {
        slug: "nuget",
        name: "NuGet",
        default_endpoint: "https://api.nuget.org/v3/index.json",
    },
];

/// Look up an ecosystem by slug.
pub fn ecosystem(slug: &str) -> Option<&'static Ecosystem> {
    ECOSYSTEMS.iter().find(|e| e.slug == slug)
}

/// Best ecosystem match for a free-text query (the type-ahead "jump" box).
///
/// Priority: an exact slug/name match, then a prefix match, then a substring
/// match — so typing `r` lands on RubyGems, `ru` still RubyGems, `c` on crates,
/// `nu` on NuGet. Matching is case-insensitive; an empty query matches nothing.
pub fn match_ecosystem(query: &str) -> Option<&'static str> {
    let q = query.trim().to_lowercase();
    if q.is_empty() {
        return None;
    }
    let mut prefix: Option<&'static str> = None;
    let mut substr: Option<&'static str> = None;
    for e in ECOSYSTEMS {
        let slug = e.slug.to_lowercase();
        let name = e.name.to_lowercase();
        if slug == q || name == q {
            return Some(e.slug);
        }
        if prefix.is_none() && (slug.starts_with(&q) || name.starts_with(&q)) {
            prefix = Some(e.slug);
        }
        if substr.is_none() && (slug.contains(&q) || name.contains(&q)) {
            substr = Some(e.slug);
        }
    }
    prefix.or(substr)
}

/// How the engine classes a capability's findings — mirrors `detect.Class`
/// (`evidence` / `trigger` / `context`) plus a `Module` bucket for the
/// supporting packages (`ioc`, `badhash`, `goodkeys`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// Factual malicious evidence — any one finding mints on its own.
    Evidence,
    /// Weak corroborating signal — only mints in combination (the gate).
    Trigger,
    /// Reputation/risk signal — recorded as metadata, never mints alone.
    Context,
    /// A supporting engine module rather than a `Detect` detector.
    Module,
}

impl Class {
    pub fn label(self) -> &'static str {
        match self {
            Class::Evidence => "evidence",
            Class::Trigger => "trigger",
            Class::Context => "context",
            Class::Module => "module",
        }
    }

    /// Chip colour for the class badge.
    pub fn color(self) -> Color32 {
        match self {
            Class::Evidence => Color32::from_rgb(0xd9, 0x4f, 0x4f), // red — mints
            Class::Trigger => Color32::from_rgb(0xd9, 0x95, 0x3f),  // amber — combines
            Class::Context => Color32::from_rgb(0x5b, 0x8d, 0xc9),  // blue — metadata
            Class::Module => Color32::from_rgb(0x4f, 0xa6, 0x7a),   // green — module
        }
    }
}

/// Which ecosystems a capability applies to.
pub enum Support {
    /// Every ecosystem.
    All,
    /// Only the listed slugs.
    Only(&'static [&'static str]),
}

impl Support {
    pub fn includes(&self, slug: &str) -> bool {
        match self {
            Support::All => true,
            Support::Only(slugs) => slugs.contains(&slug),
        }
    }
}

/// One engine capability (a `Detect` detector or a supporting module).
pub struct Capability {
    /// Stable key used in the config map and the save payload.
    pub key: &'static str,
    /// Display name.
    pub name: &'static str,
    /// One-line description (shown as a hover tooltip).
    pub detail: &'static str,
    /// Finding class.
    pub class: Class,
    /// Go symbol / signal-id family this maps to, for cross-checking the engine.
    pub engine_ref: &'static str,
    /// Ecosystems this capability is meaningful for.
    pub support: Support,
}

/// One badnet feed source and the parser the Go module should use for it.
///
/// This catalog is written to `badnet/data/feeds.json` by `just gen-defaults`.
/// The Go `badnet` package embeds that generated file and falls back to its
/// compiled defaults if the file is unavailable, so downstream binaries that
/// vendor/import the module get the same feed/parser contract at runtime.
pub struct FeedSource {
    /// Stable key used in reports and generated source headers.
    pub key: &'static str,
    /// Human-friendly source name.
    pub name: &'static str,
    /// Feed URL fetched by `badnet.Fetch`.
    pub url: &'static str,
    /// Parser key understood by `badnet.parseFeed`.
    pub parser: &'static str,
    /// Why the feed belongs in the known-bad network set.
    pub detail: &'static str,
}

/// Public badnet feeds, ordered deterministically for stable generated output.
pub const FEED_SOURCES: &[FeedSource] = &[
    FeedSource {
        key: "dshield-block",
        name: "DShield block list",
        url: "https://www.dshield.org/block.txt",
        parser: "iplist",
        detail: "DShield suspicious source IP blocklist.",
    },
    FeedSource {
        key: "dshield-ipsascii",
        name: "DShield IPs ASCII",
        url: "https://www.dshield.org/ipsascii.html",
        parser: "iplist",
        detail: "DShield top attacking IPs in plain text.",
    },
    FeedSource {
        key: "crowdsec-intelligence",
        name: "CrowdSec Intelligence Feed",
        url: "https://feeds.crowdsec.net/free/2be9a716-39b8-5c18-bc9e-4ba7aefd8831.json",
        parser: "misp",
        detail: "CrowdSec malicious intelligence feed in MISP JSON form.",
    },
    FeedSource {
        key: "dandelionsprout-antimalware",
        name: "DandelionSprout Anti-Malware Hosts",
        url: "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt",
        parser: "hosts",
        detail: "Anti-malware hosts-file blocklist.",
    },
    FeedSource {
        key: "feodotracker-recommended",
        name: "Feodo Tracker recommended C2 IPs",
        url: "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        parser: "iplist",
        detail: "Low-false-positive active botnet C2 IP list.",
    },
    FeedSource {
        key: "urlhaus-hosts",
        name: "URLhaus malware hosts",
        url: "https://urlhaus.abuse.ch/downloads/hostfile/",
        parser: "hosts",
        detail: "Active malware-delivery hostnames in hosts-file format.",
    },
    FeedSource {
        key: "isc-intelfeed",
        name: "SANS ISC Intel Feed",
        url: "https://isc.sans.edu/api/intelfeed",
        parser: "mixed",
        detail: "SANS ISC mixed IOC feed.",
    },
    FeedSource {
        key: "isc-cloudips",
        name: "SANS ISC cloud IPs",
        url: "https://isc.sans.edu/api/cloudips",
        parser: "iplist",
        detail: "SANS ISC cloud IP threat feed.",
    },
    FeedSource {
        key: "firehol-level3",
        name: "FireHOL level 3",
        url: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset",
        parser: "netset",
        detail: "FireHOL level 3 netset, reduced to individual IPs.",
    },
    FeedSource {
        key: "binarydefense-banlist",
        name: "Binary Defense banlist",
        url: "https://binarydefense.com/banlist.txt",
        parser: "iplist",
        detail: "Binary Defense observed attacker IPs.",
    },
    FeedSource {
        key: "aper-phishing-reply",
        name: "APER phishing reply addresses",
        url: "https://svn.code.sf.net/p/aper/code/phishing_reply_addresses",
        parser: "emails",
        detail: "Threat-actor email addresses observed in phishing replies.",
    },
    FeedSource {
        key: "projecthoneypot-p-rss",
        name: "Project Honey Pot phishing RSS",
        url: "https://www.projecthoneypot.org/list_of_ips.php?t=p&rss=1",
        parser: "rss",
        detail: "Project Honey Pot phishing IP RSS feed.",
    },
    FeedSource {
        key: "projecthoneypot-rss",
        name: "Project Honey Pot RSS",
        url: "https://www.projecthoneypot.org/list_of_ips.php?rss=1",
        parser: "rss",
        detail: "Project Honey Pot IP RSS feed.",
    },
    FeedSource {
        key: "cinsscore-badguys",
        name: "CINS Score badguys",
        url: "http://cinsscore.com/list/ci-badguys.txt",
        parser: "iplist",
        detail: "CINS Score suspicious IP list.",
    },
    FeedSource {
        key: "alienvault-generic",
        name: "AlienVault generic reputation",
        url: "https://reputation.alienvault.com/reputation.generic",
        parser: "iplist",
        detail: "AlienVault reputation generic IP feed.",
    },
    FeedSource {
        key: "alienvault-data",
        name: "AlienVault reputation data",
        url: "https://reputation.alienvault.com/reputation.data",
        parser: "iplist",
        detail: "AlienVault reputation data IP feed.",
    },
    FeedSource {
        key: "bruteforceblocker",
        name: "BruteforceBlocker",
        url: "https://danger.rulez.sk/projects/bruteforceblocker/blist.php",
        parser: "iplist",
        detail: "BruteforceBlocker IP list.",
    },
];

/// The full capability catalog, ordered roughly strongest-evidence first.
pub const CAPABILITIES: &[Capability] = &[
    Capability {
        key: "manifest-patterns",
        name: "Manifest / build-script patterns",
        detail: "Download-and-execute, reverse shells, eval/base64 and other patterns matched against the primary build/manifest script.",
        class: Class::Evidence,
        engine_ref: "detect.Detect → pkgbuild_analysis",
        support: Support::All,
    },
    Capability {
        key: "source-url-patterns",
        name: "Source-URL patterns",
        detail: "Suspicious download URLs declared by the manifest (paste sites, IP literals, shorteners).",
        class: Class::Evidence,
        engine_ref: "detect.Detect → source_url_analysis",
        support: Support::All,
    },
    Capability {
        key: "gtfobins",
        name: "GTFOBins LOLBin analysis",
        detail: "Living-off-the-land binary invocations used to execute, escalate or exfiltrate.",
        class: Class::Evidence,
        engine_ref: "detect.Detect → gtfobins_analysis",
        support: Support::All,
    },
    Capability {
        key: "shell-obfuscation",
        name: "Shell-obfuscation & high-entropy heredoc",
        detail: "Variable-concat exec, obfuscation, and the SA-HIGH-ENTROPY-HEREDOC payload trigger (combines via the gate).",
        class: Class::Evidence,
        engine_ref: "detect.analyzeShell (SA-*)",
        support: Support::All,
    },
    Capability {
        key: "install-script",
        name: "Install-hook script analysis",
        detail: "Runs the pattern + shell detectors over install/lifecycle hooks (AUR .install, npm pre/post-install, init.ps1, …).",
        class: Class::Evidence,
        engine_ref: "detect.Detect → install_script_analysis",
        support: Support::Only(&["aur", "homebrew", "npm", "pypi", "rubygems", "nuget"]),
    },
    Capability {
        key: "bad-actor-behaviors",
        name: "Registry-native bad-actor behaviours",
        detail: "Multi-line supply-chain TTPs the single-line pattern DB can't capture: global install-hook persistence, .pth auto-import, npm decode+egress hooks, setup.py credential exfil, build.rs cargo-config persistence, NuGet reflective-load egress — each carrying an intent qualification (the benign-vs-malicious differentiator).",
        class: Class::Evidence,
        engine_ref: "detect.analyzeBadActorBehaviors (behaviors.go)",
        support: Support::Only(&["npm", "pypi", "rubygems", "cargo", "nuget"]),
    },
    Capability {
        key: "onion-c2",
        name: "Tor .onion C2 / exfil source",
        detail: "A .onion address in the manifest, install scripts or latest diff — a common C2/exfil channel.",
        class: Class::Evidence,
        engine_ref: "detect.analyzeOnion (P-ONION-C2)",
        support: Support::All,
    },
    Capability {
        key: "homograph",
        name: "IDN homograph / mixed-script URL",
        detail: "Mixed-script (Latin+Cyrillic/Greek) hostnames in source URLs — a review-evasion technique (CWE-1007).",
        class: Class::Evidence,
        engine_ref: "detect.analyzeHomograph",
        support: Support::All,
    },
    Capability {
        key: "name-typosquat",
        name: "Typosquat / brand-impersonation",
        detail: "Package names impersonating popular packages or brands via look-alike or impersonation suffixes.",
        class: Class::Evidence,
        engine_ref: "detect.analyzeName",
        support: Support::All,
    },
    Capability {
        key: "bin-source",
        name: "`-bin` source/upstream verification",
        detail: "A -bin package whose download host differs from its declared upstream (AUR binary-package convention).",
        class: Class::Evidence,
        engine_ref: "detect.analyzeBinSource",
        support: Support::Only(&["aur"]),
    },
    Capability {
        key: "ownership-hijack",
        name: "Ownership / hijack triggers",
        detail: "Cross-registry ownership-transfer, orphan-adoption, new-maintainer and known-bad-owner triggers (the combination gate).",
        class: Class::Trigger,
        engine_ref: "detect.OwnershipTriggers (MT-*)",
        support: Support::All,
    },
    Capability {
        key: "orphan-takeover",
        name: "Orphan / abandonment takeover",
        detail: "Submitter≠maintainer plus a new git author on an established package — an orphan-takeover pattern.",
        class: Class::Evidence,
        engine_ref: "detect.analyzeOrphanTakeover",
        support: Support::Only(&["aur", "homebrew"]),
    },
    Capability {
        key: "manifest-diff",
        name: "Build-script revision diff",
        detail: "Newly introduced network calls or changed checksum/source between the prior and current manifest revision.",
        class: Class::Evidence,
        engine_ref: "detect.analyzePkgbuildDiff",
        support: Support::All,
    },
    Capability {
        key: "git-history",
        name: "Git-history temporal analysis",
        detail: "Single-commit history, package age and author-change signals from the package's source repo.",
        class: Class::Context,
        engine_ref: "detect.analyzeGitHistory",
        support: Support::Only(&["aur", "homebrew"]),
    },
    Capability {
        key: "checksum",
        name: "Checksum / integrity hygiene",
        detail: "Missing, all-SKIP or weak (md5/sha1) checksum arrays in the manifest (PKGBUILD-style sha256sums).",
        class: Class::Context,
        engine_ref: "detect.analyzeChecksum",
        support: Support::Only(&["aur", "homebrew"]),
    },
    Capability {
        key: "metadata-reputation",
        name: "Reputation metadata",
        detail: "Votes/popularity, missing license/URL and orphan flags — risk context, never mints alone.",
        class: Class::Context,
        engine_ref: "detect.analyzeMetadata",
        support: Support::All,
    },
    Capability {
        key: "maintainer-batch",
        name: "Maintainer batch-upload analysis",
        detail: "Detects a maintainer pushing many packages at once — a mass-upload supply-chain pattern.",
        class: Class::Context,
        engine_ref: "detect.analyzeMaintainer",
        support: Support::All,
    },
    Capability {
        key: "github-stars",
        name: "Upstream GitHub reputation",
        detail: "Low-star or 404 upstream GitHub repositories — a weak credibility signal.",
        class: Class::Context,
        engine_ref: "detect.analyzeGithubStars",
        support: Support::All,
    },
    Capability {
        key: "registry-comments",
        name: "Registry comment scanning",
        detail: "Scans recent registry comment bodies for warning signals (AUR has user comments).",
        class: Class::Context,
        engine_ref: "detect.analyzeAurComments",
        support: Support::Only(&["aur"]),
    },
    Capability {
        key: "badhash",
        name: "Known-bad artifact-hash set",
        detail: "Case-insensitive known-bad hash set (embedded seed + MalwareIoc rows) — a hash hit mints on its own.",
        class: Class::Module,
        engine_ref: "badhash.Set",
        support: Support::All,
    },
    Capability {
        key: "ioc-extract",
        name: "IOC + artifact-hash extraction",
        detail: "Extracts domains, URLs, IPs, file hashes, install commands, wallets and exfil endpoints from a package.",
        class: Class::Module,
        engine_ref: "ioc.Extract",
        support: Support::All,
    },
    Capability {
        key: "goodkeys",
        name: "Known-good signing-key allowlist",
        detail: "Allowlists trusted platform signing keys/identities (GitHub web-flow, Dependabot, …) to suppress false positives.",
        class: Class::Module,
        engine_ref: "goodkeys.Set",
        support: Support::All,
    },
    Capability {
        key: "ioc-scan",
        name: "STIX domain/IP IOC filesystem scan",
        detail: "Pulls domain/IP/URL indicators from the public STIX feeds (cached to the OS temp dir with a TTL) and scans a working directory — and optionally ELF binaries — for files referencing known-bad infrastructure.",
        class: Class::Module,
        engine_ref: "iocscan.Scan",
        support: Support::All,
    },
];

/// The capabilities supported by a given ecosystem, in catalog order.
pub fn capabilities_for(slug: &str) -> Vec<&'static Capability> {
    CAPABILITIES
        .iter()
        .filter(|c| c.support.includes(slug))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn count(slug: &str) -> usize {
        capabilities_for(slug).len()
    }

    #[test]
    fn capability_keys_are_unique() {
        let mut keys: Vec<&str> = CAPABILITIES.iter().map(|c| c.key).collect();
        keys.sort_unstable();
        let before = keys.len();
        keys.dedup();
        assert_eq!(before, keys.len(), "duplicate capability key in catalog");
    }

    #[test]
    fn every_ecosystem_supports_something() {
        for eco in ECOSYSTEMS {
            assert!(count(eco.slug) > 0, "{} supports no capabilities", eco.slug);
        }
    }

    #[test]
    fn aur_supports_all_but_registry_native() {
        // AUR is the engine's reference ecosystem (the traur origin): it supports
        // every capability EXCEPT `bad-actor-behaviors`, whose npm/PyPI/RubyGems/
        // Cargo/NuGet lifecycle TTPs (behaviors.go) have no equivalent in AUR's
        // PKGBUILD/makepkg model.
        let aur: std::collections::HashSet<&str> =
            capabilities_for("aur").iter().map(|c| c.key).collect();
        for cap in CAPABILITIES {
            let want = cap.key != "bad-actor-behaviors";
            assert_eq!(
                aur.contains(cap.key),
                want,
                "aur support mismatch for {}",
                cap.key
            );
        }
    }

    #[test]
    fn support_matrix_matches_engine() {
        // Counts derived from the per-capability support sets — a guard against
        // accidental matrix edits.
        assert_eq!(count("aur"), 22); // no bad-actor-behaviors (PKGBUILD model)
        assert_eq!(count("homebrew"), 20); // no -bin, no registry-comments, no bad-actor-behaviors
        assert_eq!(count("npm"), 18); // +install-script +bad-actor-behaviors over the 16 universal
        assert_eq!(count("pypi"), 18);
        assert_eq!(count("rubygems"), 18);
        assert_eq!(count("nuget"), 18);
        assert_eq!(count("go"), 16); // universal only — no install hooks
        assert_eq!(count("cargo"), 17); // +bad-actor-behaviors (build.rs TTPs)
    }

    #[test]
    fn install_script_excludes_go_and_cargo() {
        for slug in ["go", "cargo"] {
            assert!(
                !capabilities_for(slug)
                    .iter()
                    .any(|c| c.key == "install-script"),
                "{slug} should not list install-script"
            );
        }
    }

    #[test]
    fn ecosystem_lookup_round_trips() {
        for eco in ECOSYSTEMS {
            assert_eq!(ecosystem(eco.slug).map(|e| e.slug), Some(eco.slug));
        }
        assert!(ecosystem("does-not-exist").is_none());
    }

    #[test]
    fn jump_matcher_resolves_typeahead() {
        assert_eq!(match_ecosystem(""), None);
        assert_eq!(match_ecosystem("npm"), Some("npm")); // exact slug
        assert_eq!(match_ecosystem("Homebrew"), Some("homebrew")); // exact name
        assert_eq!(match_ecosystem("ru"), Some("rubygems")); // prefix
        assert_eq!(match_ecosystem("crat"), Some("cargo")); // name prefix → crates.io
        assert_eq!(match_ecosystem("nu"), Some("nuget")); // prefix
        assert_eq!(match_ecosystem("zzz"), None);
    }
}
